//! Transport-only units do not pause or hold a running producer.
use super::{
    Command, NodeHandle,
    tests::{config, core, type2},
};
use std::{
    sync::{Arc, mpsc},
    time::Instant,
};
use tokio::sync::{Semaphore, oneshot};

fn detached(config: &crate::config::Config) -> (NodeHandle, mpsc::Receiver<Command>) {
    let core = core(config);
    let mut node = core.handle.clone();
    let (sender, receive) = mpsc::channel();
    node.sender = sender;
    (node, receive)
}

type Reply = Result<(crate::protocol::TransactionStatus, crate::protocol::Head), String>;

fn enqueue(node: &NodeHandle) -> oneshot::Receiver<Reply> {
    let slot = node.queued.clone().try_acquire_owned().unwrap();
    let (reply, result) = oneshot::channel();
    node.sender
        .send(Command::Submit {
            raw: type2(10, 2),
            head: node.view().unwrap().head.clone(),
            arrived: Instant::now(),
            slot,
            reply,
        })
        .map_err(|_| ())
        .expect("Test receiver must be available");
    result
}

async fn receive(receive: &mpsc::Receiver<Command>) -> Command {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match receive.try_recv() {
                Ok(command) => break command,
                Err(mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(mpsc::TryRecvError::Disconnected) => panic!("Test receiver disconnected"),
            }
        }
    })
    .await
    .expect("Queued test command must become available")
}

#[tokio::test]
async fn full_queue_waits_without_refusal_and_cancellation_keeps_command_permit() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    config.genesis.capacity.max_pending = 1;
    let (node, receiver) = detached(&config);
    let waiter = enqueue(&node);
    assert_eq!(node.queued.available_permits(), 0);
    let request = node.clone();
    let (started, began) = oneshot::channel();
    let waiting = tokio::spawn(async move {
        started.send(()).unwrap();
        request.submit(type2(10, 2)).await
    });
    began.await.unwrap();
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished());
    assert_eq!(node.pending_count(), 0);
    drop(waiter);
    assert_eq!(node.queued.available_permits(), 0);
    drop(receiver.recv().unwrap());
    let command = receive(&receiver).await;
    assert!(matches!(&command, Command::Submit { head, .. } if head.height == 0));
    drop(command);
    assert!(
        waiting
            .await
            .unwrap()
            .unwrap_err()
            .starts_with("Outcome ambiguous;")
    );
    assert_eq!(node.queued.available_permits(), 1);
}

#[tokio::test]
async fn stop_wakes_waiting_requests_and_keeps_queued_command_order() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    config.genesis.capacity.max_pending = 1;
    let (node, receive) = detached(&config);
    let waiter = enqueue(&node);
    let request = node.clone();
    let (started, began) = oneshot::channel();
    let waiting = tokio::spawn(async move {
        started.send(()).unwrap();
        request.submit(type2(10, 2)).await
    });
    began.await.unwrap();
    tokio::task::yield_now().await;
    node.stop().await;
    assert_eq!(
        waiting.await.unwrap().unwrap_err(),
        "Node stopping before admission"
    );
    assert!(node.queued.is_closed());
    drop(waiter);
    assert_eq!(node.queued.available_permits(), 0);
    assert!(matches!(receive.recv().unwrap(), Command::Submit { .. }));
    assert!(matches!(receive.recv().unwrap(), Command::Stop));
    assert_eq!(node.queued.available_permits(), 1);
}

#[tokio::test]
async fn failed_send_and_receiver_drop_release_permits() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path(), 0);
    let (node, receive) = detached(&config);
    let waiter = enqueue(&node);
    assert_eq!(
        node.queued.available_permits(),
        config.genesis.capacity.max_pending - 1
    );
    drop(receive);
    assert_eq!(
        node.queued.available_permits(),
        config.genesis.capacity.max_pending
    );
    assert!(waiter.await.is_err());
    assert_eq!(
        node.submit(type2(10, 2)).await.unwrap_err(),
        "Admission queue unavailable or full"
    );
    assert_eq!(
        node.queued.available_permits(),
        config.genesis.capacity.max_pending
    );
    assert!(node.submit(Vec::new()).await.is_err());
    assert_eq!(
        node.queued.available_permits(),
        config.genesis.capacity.max_pending
    );
}

#[test]
fn reservation_is_bounded_under_concurrent_senders() {
    let queued = Arc::new(Semaphore::new(1));
    let held = queued.clone().try_acquire_owned().unwrap();
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let queued = queued.clone();
            std::thread::spawn(move || assert!(queued.try_acquire_owned().is_err()))
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(queued.available_permits(), 0);
    drop(held);
    assert_eq!(queued.available_permits(), 1);
}

#[tokio::test]
async fn maximum_declared_idle_capacity_has_no_capacity_sized_transport_array() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    config.genesis.capacity.max_pending = u32::MAX as usize;
    let (node, worker) = super::start(&config).unwrap();
    assert_eq!(node.capacity().max_pending, u32::MAX as usize);
    assert_eq!(node.queued.available_permits(), u32::MAX as usize);
    assert_eq!(node.pending_count(), 0);
    node.stop().await;
    tokio::task::spawn_blocking(move || worker.join().unwrap())
        .await
        .unwrap();
    assert!(node.failure().is_none());
}
