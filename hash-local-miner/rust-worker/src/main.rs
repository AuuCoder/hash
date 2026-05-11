mod metal_backend;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::Serialize;
use sha3::{Digest, Keccak256};
use std::env;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
enum CliError {
    Message(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Message(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for CliError {}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum Backend {
    Cpu,
    Metal,
}

impl Backend {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "cpu" => Ok(Self::Cpu),
            "metal" => Ok(Self::Metal),
            other => Err(CliError::Message(format!("invalid --backend: {other}"))),
        }
    }
}

#[derive(Clone)]
struct Config {
    challenge: [u8; 32],
    difficulty: [u8; 32],
    threads: usize,
    progress_ms: u64,
    backend: Backend,
    batch_size: u32,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum Event {
    #[serde(rename = "ready")]
    Ready {
        version: &'static str,
        threads: usize,
        backend: Backend,
    },
    #[serde(rename = "progress")]
    Progress {
        hashes: u64,
        hashrate: f64,
        elapsed_ms: u128,
    },
    #[serde(rename = "hit")]
    Hit {
        nonce_hex: String,
        digest_hex: String,
        hashes: u64,
        elapsed_ms: u128,
    },
    #[serde(rename = "stopped")]
    Stopped { hashes: u64, elapsed_ms: u128 },
}

struct Hit {
    nonce: [u8; 32],
    digest: [u8; 32],
}

fn main() {
    if let Err(err) = run() {
        emit_error(&err.to_string());
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let cfg = parse_args()?;
    emit(&Event::Ready {
        version: env!("CARGO_PKG_VERSION"),
        threads: cfg.threads,
        backend: cfg.backend,
    });

    match cfg.backend {
        Backend::Cpu => run_cpu(&cfg),
        Backend::Metal => metal_backend::run(&cfg),
    }
}

fn run_cpu(cfg: &Config) -> Result<(), CliError> {
    let stop = Arc::new(AtomicBool::new(false));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Hit>();
    let started = Instant::now();
    let mut joins = Vec::with_capacity(cfg.threads);

    for worker_id in 0..cfg.threads {
        let stop_flag = Arc::clone(&stop);
        let hash_counter = Arc::clone(&total_hashes);
        let tx_hit = tx.clone();
        let challenge = cfg.challenge;
        let difficulty = cfg.difficulty;
        joins.push(thread::spawn(move || {
            worker_loop(worker_id, challenge, difficulty, stop_flag, hash_counter, tx_hit);
        }));
    }
    drop(tx);

    loop {
        if let Ok(hit) = rx.recv_timeout(Duration::from_millis(cfg.progress_ms)) {
            stop.store(true, Ordering::Relaxed);
            let hashes = total_hashes.load(Ordering::Relaxed);
            emit(&Event::Hit {
                nonce_hex: hex_string(&hit.nonce),
                digest_hex: hex_string(&hit.digest),
                hashes,
                elapsed_ms: started.elapsed().as_millis(),
            });
            break;
        }

        let elapsed = started.elapsed();
        let hashes = total_hashes.load(Ordering::Relaxed);
        emit_progress(hashes, elapsed);
    }

    for join in joins {
        let _ = join.join();
    }

    let hashes = total_hashes.load(Ordering::Relaxed);
    emit(&Event::Stopped {
        hashes,
        elapsed_ms: started.elapsed().as_millis(),
    });

    Ok(())
}

fn worker_loop(
    worker_id: usize,
    challenge: [u8; 32],
    difficulty: [u8; 32],
    stop: Arc<AtomicBool>,
    total_hashes: Arc<AtomicU64>,
    tx_hit: mpsc::Sender<Hit>,
) {
    let mut seed = [0u8; 32];
    let mut sys_rng = rand::thread_rng();
    sys_rng.fill_bytes(&mut seed);
    seed[0] ^= worker_id as u8;
    let mut rng = StdRng::from_seed(seed);

    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce[..16]);
    let mut counter = u128::from_be_bytes(nonce[16..32].try_into().unwrap());
    let mut hasher = Keccak256::new();
    let mut local_hashes: u64 = 0;

    while !stop.load(Ordering::Relaxed) {
        nonce[16..32].copy_from_slice(&counter.to_be_bytes());
        counter = counter.wrapping_add(1);

        hasher.update(challenge);
        hasher.update(nonce);
        let digest = hasher.finalize_reset();

        local_hashes = local_hashes.wrapping_add(1);
        if local_hashes >= 4096 {
            total_hashes.fetch_add(local_hashes, Ordering::Relaxed);
            local_hashes = 0;
        }

        if digest.as_slice() < &difficulty {
            if local_hashes > 0 {
                total_hashes.fetch_add(local_hashes, Ordering::Relaxed);
            }
            let mut digest_bytes = [0u8; 32];
            digest_bytes.copy_from_slice(&digest);
            let _ = tx_hit.send(Hit {
                nonce,
                digest: digest_bytes,
            });
            stop.store(true, Ordering::Relaxed);
            return;
        }
    }

    if local_hashes > 0 {
        total_hashes.fetch_add(local_hashes, Ordering::Relaxed);
    }
}

fn parse_args() -> Result<Config, CliError> {
    let mut challenge = None;
    let mut difficulty = None;
    let mut threads = None;
    let mut progress_ms = 1000u64;
    let mut backend = Backend::Cpu;
    let mut batch_size = 1_048_576u32;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--challenge" => challenge = Some(parse_hex_32(&next_arg(&mut args, "--challenge")?)?),
            "--difficulty" => {
                difficulty = Some(parse_hex_32(&next_arg(&mut args, "--difficulty")?)?)
            }
            "--threads" => {
                let raw = next_arg(&mut args, "--threads")?;
                let parsed = raw
                    .parse::<usize>()
                    .map_err(|_| CliError::Message(format!("invalid --threads: {raw}")))?;
                if parsed == 0 {
                    return Err(CliError::Message("--threads must be >= 1".into()));
                }
                threads = Some(parsed);
            }
            "--progress-ms" => {
                let raw = next_arg(&mut args, "--progress-ms")?;
                progress_ms = raw
                    .parse::<u64>()
                    .map_err(|_| CliError::Message(format!("invalid --progress-ms: {raw}")))?;
            }
            "--backend" => {
                backend = Backend::parse(&next_arg(&mut args, "--backend")?)?;
            }
            "--batch-size" => {
                let raw = next_arg(&mut args, "--batch-size")?;
                let parsed = raw
                    .parse::<u32>()
                    .map_err(|_| CliError::Message(format!("invalid --batch-size: {raw}")))?;
                if parsed == 0 {
                    return Err(CliError::Message("--batch-size must be >= 1".into()));
                }
                batch_size = parsed;
            }
            other => {
                return Err(CliError::Message(format!("unknown arg: {other}")));
            }
        }
    }

    Ok(Config {
        challenge: challenge.ok_or_else(|| CliError::Message("missing --challenge".into()))?,
        difficulty: difficulty.ok_or_else(|| CliError::Message("missing --difficulty".into()))?,
        threads: threads.unwrap_or(1),
        progress_ms,
        backend,
        batch_size,
    })
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, CliError> {
    args.next()
        .ok_or_else(|| CliError::Message(format!("missing value for {flag}")))
}

pub(crate) fn parse_hex_32(input: &str) -> Result<[u8; 32], CliError> {
    let raw = input.strip_prefix("0x").unwrap_or(input);
    if raw.len() != 64 {
        return Err(CliError::Message(format!(
            "expected 32-byte hex for {input}, got {} chars",
            raw.len()
        )));
    }

    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|_| CliError::Message(format!("invalid hex: {input}")))?;
    }
    Ok(out)
}

pub(crate) fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn emit_progress(hashes: u64, elapsed: Duration) {
    let seconds = elapsed.as_secs_f64();
    emit(&Event::Progress {
        hashes,
        hashrate: if seconds > 0.0 {
            hashes as f64 / seconds
        } else {
            0.0
        },
        elapsed_ms: elapsed.as_millis(),
    });
}

pub(crate) fn emit(event: &Event) {
    println!("{}", serde_json::to_string(event).unwrap());
}

fn emit_error(message: &str) {
    let payload = serde_json::json!({
        "type": "error",
        "message": message,
    });
    println!("{payload}");
}

const HEX: &[u8; 16] = b"0123456789abcdef";
