//! Independent immutable signature/envelope work. Threads exist only for an
//! already queued chunk; the owning core counts as one verification worker.
//! An operator-selected factor can intentionally oversubscribe logical CPUs.
use crate::execution::{self, PreparedTransaction};
use std::thread;

pub(super) fn worker_budget(available: usize) -> usize {
    available.saturating_sub(1).max(1)
}

pub(super) fn detected_budget() -> (usize, usize) {
    let available = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    (available, worker_budget(available))
}

pub(super) fn configured_budget(available: usize, factor: usize) -> Result<usize, String> {
    if factor == 0 {
        return Err("Verification workers per CPU must be positive".into());
    }
    worker_budget(available)
        .checked_mul(factor)
        .ok_or_else(|| "Verification worker count overflows platform limit".into())
}

pub(super) fn active_workers(budget: usize, inputs: usize) -> usize {
    budget.max(1).min(inputs)
}

pub(super) fn prepare_parallel(
    inputs: &[&[u8]],
    chain_id: u64,
    budget: usize,
) -> Result<Vec<Result<PreparedTransaction, String>>, String> {
    let workers = active_workers(budget, inputs.len());
    if workers == 0 {
        return Ok(Vec::new());
    }
    let prepare = |part: &[&[u8]]| {
        part.iter()
            .map(|raw| execution::prepare_for_chain(raw, chain_id))
            .collect::<Vec<_>>()
    };
    if workers == 1 {
        return Ok(prepare(inputs));
    }
    thread::scope(|scope| {
        let base = inputs.len() / workers;
        let remainder = inputs.len() % workers;
        let first_end = base + usize::from(remainder > 0);
        let mut spawned = Vec::with_capacity(workers - 1);
        for worker in 1..workers {
            let start = worker * base + worker.min(remainder);
            let end = start + base + usize::from(worker < remainder);
            let part = &inputs[start..end];
            spawned.push(scope.spawn(move || prepare(part)));
        }
        let mut results = prepare(&inputs[..first_end]);
        for worker in spawned {
            results.extend(
                worker
                    .join()
                    .map_err(|_| "Signature preparation worker failed")?,
            );
        }
        Ok(results)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_cpu_budget_and_active_tasks_are_not_hardcoded() {
        for (available, expected) in [(1, 1), (2, 1), (8, 7), (16, 15), (32, 31)] {
            let budget = worker_budget(available);
            assert_eq!(budget, expected);
            for count in [0, 1, 3, 100, 1000] {
                let active = active_workers(budget, count);
                assert!(active <= budget && active <= count);
                assert_eq!(active, budget.min(count));
            }
        }
    }

    #[test]
    fn configured_factor_is_dynamic_positive_and_checked() {
        for available in [1, 2, 8, 16, 32, 64] {
            let base = worker_budget(available);
            assert_eq!(configured_budget(available, 1).unwrap(), base);
            assert_eq!(configured_budget(available, 10).unwrap(), base * 10);
        }
        assert_eq!(configured_budget(16, 10).unwrap(), 150);
        assert_eq!(configured_budget(64, 10).unwrap(), 630);
        assert_eq!(configured_budget(1, 10).unwrap(), 10);
        assert!(configured_budget(16, 0).is_err());
        assert!(configured_budget(usize::MAX, 2).is_err());
        assert!(configured_budget(16, usize::MAX).is_err());
    }

    #[test]
    fn parallel_preparation_preserves_input_order_and_individual_rejection() {
        use crate::{development, protocol::CHAIN_ID};
        use alloy_primitives::{Address, U256};
        let first = development::sign(
            0,
            Some(Address::repeat_byte(0x61)),
            U256::from(1),
            vec![],
            21_000,
        )
        .unwrap();
        let second = development::sign(
            1,
            Some(Address::repeat_byte(0x62)),
            U256::from(2),
            vec![],
            21_000,
        )
        .unwrap();
        let raw = [first, vec![0xff], second];
        let inputs: Vec<_> = raw.iter().map(Vec::as_slice).collect();
        let prepared = prepare_parallel(&inputs, CHAIN_ID, worker_budget(8)).unwrap();
        assert_eq!(prepared.len(), inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            match (
                &prepared[index],
                execution::prepare_for_chain(input, CHAIN_ID),
            ) {
                (Ok(parallel), Ok(serial)) => {
                    assert_eq!(parallel.info().hash, serial.info().hash);
                    assert_eq!(parallel.info().sender, serial.info().sender);
                    assert!(parallel.matches(input, CHAIN_ID));
                }
                (Err(parallel), Err(serial)) => assert_eq!(*parallel, serial),
                _ => panic!("Parallel signature preparation changed an input outcome"),
            }
        }
    }
}
