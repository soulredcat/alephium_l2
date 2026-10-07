//! Sleep while idle; group only commands already queued, without collection waits.
//! Durable replies precede production. Arrival times are reporting metadata.
use super::{Command, Core};
use crate::protocol::BLOCK_INTERVAL_MS;
use std::{
    sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError},
    time::{Duration, Instant},
};

fn next_deadline(core: &Core, interval: Duration) -> Option<Instant> {
    (!core.pending.is_empty() && core.handle.failure().is_none()).then(|| Instant::now() + interval)
}

fn advance_tick(previous: Instant, interval: Duration, now: Instant) -> Instant {
    if now < previous {
        return previous;
    }
    // Skip elapsed wall-clock ticks after real execution/SyncAll overruns;
    // no empty catch-up blocks are invented and no producer wait is added.
    let remainder = now.duration_since(previous).as_nanos() % interval.as_nanos();
    now + Duration::from_nanos((interval.as_nanos() - remainder) as u64)
}

pub(super) fn run(mut core: Core, receive: Receiver<Command>) {
    let interval = Duration::from_millis(BLOCK_INTERVAL_MS);
    // Monotonic arrival times are not persisted; recovered intents start here.
    let mut deadline = next_deadline(&core, interval);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        loop {
            // A full durable queue advances real production to free space;
            // no valid command is refused merely because capacity is occupied.
            if deadline.is_some_and(|deadline| Instant::now() >= deadline)
                || core.pending.len() >= core.handle.capacity.max_pending
            {
                let previous = deadline.unwrap_or_else(Instant::now);
                if core.handle.failure().is_none() && core.produce().is_err() {
                    core.fail();
                }
                let work = !core.pending.is_empty()
                    || core.handle.queued.available_permits() < core.handle.capacity.max_pending;
                deadline = (work && core.handle.failure().is_none())
                    .then(|| advance_tick(previous, interval, Instant::now()));
            }
            let command = match deadline {
                Some(deadline) => {
                    receive.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                }
                None => receive.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match command {
                Ok(Command::Submit {
                    raw,
                    head,
                    arrived,
                    slot,
                    reply,
                }) => {
                    drop(slot);
                    // Production above guarantees at least one durable slot
                    // while healthy. Validation reserves only this chunk's
                    // actual free space, independently of transport permits.
                    let available = core
                        .handle
                        .capacity
                        .max_pending
                        .saturating_sub(core.pending.len());
                    let chunk = core.handle.verification_chunk().min(available.max(1));
                    let mut group = vec![(raw, head, arrived, reply)];
                    let mut stop = false;
                    while group.len() < chunk {
                        match receive.try_recv() {
                            Ok(Command::Submit {
                                raw,
                                head,
                                arrived,
                                slot,
                                reply,
                            }) => {
                                drop(slot);
                                group.push((raw, head, arrived, reply));
                            }
                            Ok(Command::Stop) | Err(TryRecvError::Disconnected) => {
                                stop = true;
                                break;
                            }
                            Err(TryRecvError::Empty) => break,
                        }
                    }
                    let mut inputs = Vec::with_capacity(group.len());
                    let mut replies = Vec::with_capacity(group.len());
                    for (raw, head, arrived, reply) in group {
                        inputs.push(raw);
                        replies.push((head, arrived, reply));
                    }
                    let results = core.admit_queued(inputs);
                    if core.handle.failure().is_some() {
                        deadline = None;
                    } else if deadline.is_none() && !core.pending.is_empty() {
                        // Only initial idle activation uses arrival time. An
                        // active production clock is never reset by old requests.
                        let arrival_deadline = results
                            .iter()
                            .zip(&replies)
                            .filter(|(result, _)| {
                                result
                                    .as_ref()
                                    .is_ok_and(|status| status.status == "durably_accepted")
                            })
                            .map(|(_, (_, arrived, _))| *arrived + interval)
                            .min();
                        if let Some(arrival_deadline) = arrival_deadline {
                            deadline = Some(
                                deadline
                                    .map_or(arrival_deadline, |prior| prior.min(arrival_deadline)),
                            );
                        }
                    }
                    for (result, (head, _, reply)) in results.into_iter().zip(replies) {
                        let _ = reply.send(result.map(|status| (status, head)));
                    }
                    if stop {
                        break;
                    }
                }
                Ok(Command::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => (),
            }
        }
    }));
    if outcome.is_err() {
        core.fail();
    }
}
