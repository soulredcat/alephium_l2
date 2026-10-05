//! Bounded loopback RPC counter fixture; synthetic metadata is not EVM evidence.
use alephium_l2_sdk::ExpectedNetwork;
use alloy_primitives::{Address, B256, keccak256};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REQUEST: usize = 16_384;

pub(crate) struct Mock {
    endpoint: String,
    stop: Arc<AtomicBool>,
    counts: Arc<Mutex<BTreeMap<String, usize>>>,
    worker: Option<JoinHandle<()>>,
}

impl Mock {
    pub(crate) fn start(
        network: ExpectedNetwork,
        hash: B256,
        sender: Address,
        recipient: Address,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let counts = Arc::new(Mutex::new(BTreeMap::new()));
        let thread_stop = stop.clone();
        let thread_counts = counts.clone();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !thread_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                let (mut socket, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => panic!("SDK mock accept failed"),
                };
                socket.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
                socket.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
                let (path, input) = read_request(&mut socket);
                let response = if path == "GET /health" {
                    increment(&thread_counts, "health");
                    json!({
                        "status":"development", "error":null,
                        "chain_id":network.chain_id, "genesis_id":network.genesis_id,
                        "rpc_profile":network.rpc_profile, "height":0,
                        "local_commit_id":B256::repeat_byte(0x55),
                        "settlement":"unimplemented", "transaction_types":["0x0","0x2"]
                    })
                } else {
                    assert!(path == "POST /", "unexpected SDK mock endpoint");
                    assert!(
                        input["jsonrpc"] == "2.0" && input["id"].is_u64(),
                        "SDK mock request framing changed"
                    );
                    let method = input["method"].as_str().expect("mock method missing");
                    let params = input["params"].as_array().expect("mock params missing");
                    increment(&thread_counts, method);
                    let result = match method {
                        "eth_chainId" => {
                            assert!(params.is_empty(), "chain handshake params changed");
                            json!(format!("0x{:x}", network.chain_id))
                        }
                        "l2_sendRawTransaction" => {
                            assert!(
                                params.len() == 2 && params[1] == json!(network.genesis_id),
                                "submission did not carry the pinned genesis"
                            );
                            let raw = params[0]
                                .as_str()
                                .and_then(|raw| raw.strip_prefix("0x"))
                                .and_then(|raw| hex::decode(raw).ok())
                                .expect("mock envelope invalid");
                            assert!(
                                keccak256(raw) == hash,
                                "submission changed original identity"
                            );
                            // One complete request was received. Its malformed reply is
                            // intentionally ambiguous and must not trigger a second POST.
                            write_response(&mut socket, b"{");
                            continue;
                        }
                        "l2_getBalance" => {
                            assert!(
                                params.as_slice()
                                    == [json!(sender), json!("latest"), json!(network.genesis_id)],
                                "balance params were not identity pinned"
                            );
                            json!("0x7b")
                        }
                        "l2_getTransactionCount" => {
                            assert!(
                                params.len() == 3
                                    && params[0] == json!(sender)
                                    && params[2] == json!(network.genesis_id),
                                "nonce identity pin changed"
                            );
                            match params[1].as_str() {
                                Some("latest") => json!("0x7"),
                                Some("pending") => json!("0x8"),
                                _ => panic!("unexpected nonce tag"),
                            }
                        }
                        "l2_getTransactionStatus" => {
                            assert!(
                                params.as_slice() == [json!(hash), json!(network.genesis_id)],
                                "status params were not identity pinned"
                            );
                            json!({"hash":hash, "status":"committed", "block_height":1, "error":null})
                        }
                        "l2_getTransactionReceipt" => {
                            assert!(
                                params.as_slice() == [json!(hash), json!(network.genesis_id)],
                                "receipt params were not identity pinned"
                            );
                            json!({
                                "transactionHash":hash, "blockHash":B256::repeat_byte(0x77),
                                "transactionIndex":"0x0",
                                "blockNumber":"0x1", "gasUsed":"0x5208", "cumulativeGasUsed":"0x5208",
                                "effectiveGasPrice":"0x3", "status":"0x1", "type":"0x2",
                                "from":sender, "to":recipient, "contractAddress":null
                            })
                        }
                        _ => panic!("unexpected SDK mock method"),
                    };
                    json!({"jsonrpc":"2.0", "id":input["id"], "result":result})
                };
                write_response(&mut socket, &serde_json::to_vec(&response).unwrap());
            }
        });
        Self {
            endpoint,
            stop,
            counts,
            worker: Some(worker),
        }
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn finish(mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("SDK mock worker failed");
        let expected = BTreeMap::from([
            ("health".to_owned(), 1),
            ("eth_chainId".to_owned(), 1),
            ("l2_sendRawTransaction".to_owned(), 1),
            ("l2_getBalance".to_owned(), 1),
            ("l2_getTransactionCount".to_owned(), 2),
            ("l2_getTransactionStatus".to_owned(), 1),
            ("l2_getTransactionReceipt".to_owned(), 1),
        ]);
        assert_eq!(
            *self.counts.lock().unwrap(),
            expected,
            "ambiguous submission caused a retry or skipped a pinned read"
        );
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn increment(counts: &Mutex<BTreeMap<String, usize>>, method: &str) {
    *counts.lock().unwrap().entry(method.to_owned()).or_default() += 1;
}

fn read_request(socket: &mut TcpStream) -> (String, Value) {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut request = Vec::new();
    let (header_end, content_length) = loop {
        let mut chunk = [0; 1024];
        let count = read_chunk(socket, &mut chunk, deadline);
        assert!(
            count > 0 && request.len() + count <= MAX_REQUEST,
            "SDK mock header bound exceeded"
        );
        request.extend_from_slice(&chunk[..count]);
        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&request[..end]).expect("SDK mock headers invalid");
            let length = headers
                .lines()
                .skip(1)
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            assert!(
                length <= MAX_REQUEST - (end + 4),
                "SDK mock body bound exceeded"
            );
            break (end + 4, length);
        }
    };
    while request.len() < header_end + content_length {
        let mut chunk = [0; 1024];
        let count = read_chunk(socket, &mut chunk, deadline);
        assert!(
            count > 0 && request.len() + count <= MAX_REQUEST,
            "SDK mock body ended early"
        );
        request.extend_from_slice(&chunk[..count]);
    }
    let first_line = std::str::from_utf8(&request[..header_end])
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let path = first_line
        .strip_suffix(" HTTP/1.1")
        .expect("SDK mock HTTP version changed")
        .to_owned();
    let input = if content_length == 0 {
        Value::Null
    } else {
        serde_json::from_slice(&request[header_end..header_end + content_length])
            .expect("SDK mock request JSON invalid")
    };
    (path, input)
}

fn read_chunk(socket: &mut TcpStream, chunk: &mut [u8], deadline: Instant) -> usize {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .expect("SDK mock request deadline exceeded");
    socket.set_read_timeout(Some(remaining)).unwrap();
    socket.read(chunk).expect("SDK mock request read failed")
}

fn write_response(socket: &mut TcpStream, bytes: &[u8]) {
    write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len())
        .expect("SDK mock response headers failed");
    socket
        .write_all(bytes)
        .expect("SDK mock response body failed");
    socket.flush().expect("SDK mock response flush failed");
}
