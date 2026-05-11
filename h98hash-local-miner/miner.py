#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import deque
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import requests
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import keccak, to_checksum_address


CONTRACT_ADDRESS = "0x1E5adF70321CA28b3Ead70Eac545E6055E969e6f"
DEFAULT_RPC_URL = "https://ethereum-rpc.publicnode.com"
DEFAULT_POLL_INTERVAL = 8
DEFAULT_PROGRESS_MS = 1000
DEFAULT_GAS_LIMIT = 350_000
MIN_GAS_LIMIT = 220_000
MAX_GAS_LIMIT = 600_000
DEFAULT_MAX_FEE_MULTIPLIER = Decimal("3")
DEFAULT_MIN_PRIORITY_FEE_GWEI = Decimal("2.5")
DEFAULT_MAX_PENDING_SUBMISSIONS = 1
GWEI = 10**9


def load_dotenv(dotenv_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not dotenv_path.exists():
        return values

    for line_number, raw_line in enumerate(dotenv_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise ValueError(f"invalid .env line {line_number}: {raw_line}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"invalid .env line {line_number}: empty key")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def env_value(name: str, dotenv: dict[str, str], default: str | None = None) -> str | None:
    if name in os.environ:
        return os.environ[name]
    if name in dotenv:
        return dotenv[name]
    return default


def env_flag(name: str, dotenv: dict[str, str], default: bool = False) -> bool:
    raw = env_value(name, dotenv)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value for {name}: {raw}")


def env_decimal(name: str, dotenv: dict[str, str], default: Decimal) -> Decimal:
    raw = env_value(name, dotenv)
    if raw is None:
        return default
    return Decimal(raw.strip())


@dataclass
class ConfigState:
    mint_open: bool
    market_open: bool
    listing_open: bool
    buying_open: bool
    batch_open: bool
    market_mode: int
    difficulty_bits: int
    mint_price_wei: int
    mint_amount: int
    max_public_mints: int
    treasury_reserve_mints: int
    lot_size: int
    min_listing_amount: int
    max_batch_size: int
    market_fee_bps: int
    fee_recipient: str


@dataclass
class PendingSubmission:
    tx_hash: str
    nonce_hex: str
    submitted_at: float


class RpcClient:
    def __init__(self, rpc_url: str, timeout: int = 20) -> None:
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.session = requests.Session()
        self._request_id = 1

    def call(self, method: str, params: list[Any]) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        }
        self._request_id += 1
        response = self.session.post(self.rpc_url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RuntimeError(f"{method} failed: {data['error']}")
        return data["result"]

    def eth_call(self, to: str, data_hex: str, block: str = "latest") -> str:
        return self.call("eth_call", [{"to": to, "data": data_hex}, block])

    def chain_id(self) -> int:
        return int(self.call("eth_chainId", []), 16)

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def latest_block(self) -> dict[str, Any]:
        return self.call("eth_getBlockByNumber", ["latest", False])

    def gas_price(self) -> int:
        return int(self.call("eth_gasPrice", []), 16)

    def max_priority_fee(self) -> int:
        try:
            return int(self.call("eth_maxPriorityFeePerGas", []), 16)
        except Exception:
            return 2_000_000_000

    def nonce(self, address: str) -> int:
        return int(self.call("eth_getTransactionCount", [address, "pending"]), 16)

    def estimate_gas(self, tx: dict[str, str]) -> int:
        return int(self.call("eth_estimateGas", [tx]), 16)

    def send_raw_transaction(self, raw_tx_hex: str) -> str:
        return self.call("eth_sendRawTransaction", [raw_tx_hex])

    def receipt(self, tx_hash: str) -> dict[str, Any] | None:
        return self.call("eth_getTransactionReceipt", [tx_hash])


def fn_selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def encode_address(value: str) -> bytes:
    addr = bytes.fromhex(value.lower().removeprefix("0x"))
    if len(addr) != 20:
        raise ValueError(f"invalid address: {value}")
    return b"\x00" * 12 + addr


def encode_bytes16(value: bytes) -> bytes:
    if len(value) != 16:
        raise ValueError("bytes16 value must be 16 bytes")
    return value + b"\x00" * 16


def decode_uint256_words(data_hex: str) -> list[int]:
    raw = bytes.fromhex(data_hex.removeprefix("0x"))
    if len(raw) % 32 != 0:
        raise ValueError(f"unexpected ABI payload length: {len(raw)}")
    return [int.from_bytes(raw[i : i + 32], "big") for i in range(0, len(raw), 32)]


def decode_bool_word(value: int) -> bool:
    return bool(value)


def gwei_to_wei(value: Decimal) -> int:
    return int(value * Decimal(GWEI))


def default_backend() -> str:
    if sys.platform == "darwin":
        return "metal"
    return "cpu"


def default_threads() -> int:
    cores = os.cpu_count() or 4
    return max(1, min(8, cores - 1))


def default_batch_size() -> int:
    return 1_048_576


def worker_binary(root: Path) -> Path:
    suffix = ".exe" if sys.platform.startswith("win") else ""
    return root / "rust-worker" / "target" / "release" / f"h98hash-rust-worker{suffix}"


def ensure_worker_built(root: Path) -> Path:
    binary = worker_binary(root)
    if binary.exists():
        return binary

    print("[build] compiling Rust worker...", flush=True)
    build_env = os.environ.copy()
    build_env.setdefault("CARGO_HOME", str(root / ".cargo-local"))
    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd=root / "rust-worker",
        text=True,
        env=build_env,
    )
    if result.returncode != 0:
        raise RuntimeError("Rust worker build failed")
    if not binary.exists():
        raise RuntimeError(f"worker binary not found after build: {binary}")
    return binary


def read_challenge(rpc: RpcClient, miner_address: str) -> bytes:
    calldata = "0x" + (fn_selector("challengeFor(address)") + encode_address(miner_address)).hex()
    raw = bytes.fromhex(rpc.eth_call(CONTRACT_ADDRESS, calldata).removeprefix("0x"))
    if len(raw) != 32:
        raise RuntimeError(f"unexpected challengeFor payload length: {len(raw)}")
    return raw[:16]


def read_config(rpc: RpcClient) -> ConfigState:
    calldata = "0x" + fn_selector("getConfig()").hex()
    words = decode_uint256_words(rpc.eth_call(CONTRACT_ADDRESS, calldata))
    if len(words) != 16:
        raise RuntimeError(f"unexpected getConfig length: {len(words)}")
    return ConfigState(
        mint_open=decode_bool_word(words[0]),
        market_open=decode_bool_word(words[1]),
        listing_open=decode_bool_word(words[2]),
        buying_open=decode_bool_word(words[3]),
        batch_open=decode_bool_word(words[4]),
        market_mode=words[5],
        difficulty_bits=words[6],
        mint_price_wei=words[7],
        mint_amount=words[8],
        max_public_mints=words[9],
        treasury_reserve_mints=words[10],
        lot_size=words[11],
        min_listing_amount=words[12],
        max_batch_size=words[13],
        market_fee_bps=words[14],
        fee_recipient=to_checksum_address(f"0x{words[15]:040x}"),
    )


def build_mint_calldata(nonce_bytes: bytes) -> str:
    return "0x" + (fn_selector("mint(bytes16)") + encode_bytes16(nonce_bytes)).hex()


def choose_fee_params(
    rpc: RpcClient,
    min_priority_fee_wei: int,
    max_fee_multiplier: Decimal,
) -> tuple[int, int]:
    block = rpc.latest_block()
    base_fee_hex = block.get("baseFeePerGas")
    priority_fee = max(rpc.max_priority_fee(), min_priority_fee_wei)
    if base_fee_hex:
        base_fee = int(base_fee_hex, 16)
        max_fee = int(Decimal(base_fee) * max_fee_multiplier) + priority_fee
        return max_fee, priority_fee
    gas_price = max(rpc.gas_price(), priority_fee)
    return gas_price, priority_fee


def clamp_gas_limit(estimate: int) -> int:
    gas = (estimate * 3) // 2
    gas = max(gas, MIN_GAS_LIMIT)
    gas = min(gas, MAX_GAS_LIMIT)
    return gas


def run_worker(
    binary: Path,
    challenge_hex: str,
    difficulty_bits: int,
    backend: str,
    threads: int,
    batch_size: int,
    progress_ms: int,
    poll_cb,
) -> dict[str, Any]:
    proc = subprocess.Popen(
        [
            str(binary),
            "--backend",
            backend,
            "--challenge",
            challenge_hex,
            "--difficulty-bits",
            str(difficulty_bits),
            "--threads",
            str(threads),
            "--batch-size",
            str(batch_size),
            "--progress-ms",
            str(progress_ms),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    last_event: dict[str, Any] | None = None
    recent_output: deque[str] = deque(maxlen=20)

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue

            stripped = line.strip()
            if stripped:
                recent_output.append(stripped)

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            last_event = event
            event_type = event.get("type")

            if event_type == "progress":
                hashes = event["hashes"]
                rate = event["hashrate"]
                elapsed_ms = event["elapsed_ms"]
                print(
                    f"[worker] {hashes:,} hashes | {format_hashrate(rate)} | {elapsed_ms / 1000:.1f}s",
                    flush=True,
                )
                restart_reason = poll_cb()
                if restart_reason:
                    proc.terminate()
                    proc.wait(timeout=5)
                    return {"type": "restart", "reason": restart_reason}
            elif event_type == "hit":
                proc.wait(timeout=5)
                return event
            elif event_type == "error":
                proc.wait(timeout=5)
                raise RuntimeError(event.get("message", "worker error"))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    if last_event and last_event.get("type") == "stopped":
        return last_event

    exit_code = proc.returncode
    tail = "\n".join(recent_output)
    details = f"worker exited unexpectedly (code={exit_code})"
    if tail:
        details += f"\nrecent output:\n{tail}"
    raise RuntimeError(details)


def submit_solution(
    read_rpc: RpcClient,
    submit_rpc: RpcClient,
    account: LocalAccount,
    nonce_hex: str,
    mint_price_wei: int,
    min_priority_fee_wei: int,
    max_fee_multiplier: Decimal,
    gas_limit_override: int | None = None,
) -> str:
    nonce_bytes = bytes.fromhex(nonce_hex.removeprefix("0x"))
    calldata = build_mint_calldata(nonce_bytes)

    try:
        estimate = read_rpc.estimate_gas(
            {
                "from": account.address,
                "to": CONTRACT_ADDRESS,
                "data": calldata,
                "value": hex(mint_price_wei),
            }
        )
        gas_limit = clamp_gas_limit(estimate)
    except Exception:
        gas_limit = gas_limit_override or DEFAULT_GAS_LIMIT

    max_fee_per_gas, max_priority_fee_per_gas = choose_fee_params(
        read_rpc,
        min_priority_fee_wei=min_priority_fee_wei,
        max_fee_multiplier=max_fee_multiplier,
    )
    tx = {
        "chainId": read_rpc.chain_id(),
        "nonce": read_rpc.nonce(account.address),
        "to": to_checksum_address(CONTRACT_ADDRESS),
        "value": mint_price_wei,
        "data": calldata,
        "gas": gas_limit_override or gas_limit,
        "maxFeePerGas": max_fee_per_gas,
        "maxPriorityFeePerGas": max_priority_fee_per_gas,
        "type": 2,
    }

    signed = account.sign_transaction(tx)
    raw_tx = signed.raw_transaction.hex()
    if not raw_tx.startswith("0x"):
        raw_tx = "0x" + raw_tx
    return submit_rpc.send_raw_transaction(raw_tx)


def drain_pending_receipts(rpc: RpcClient, pending: list[PendingSubmission]) -> None:
    if not pending:
        return
    remaining: list[PendingSubmission] = []
    for item in pending:
        receipt = rpc.receipt(item.tx_hash)
        if receipt is None:
            remaining.append(item)
            continue

        status = int(receipt["status"], 16)
        gas_used = int(receipt["gasUsed"], 16)
        block_number = int(receipt["blockNumber"], 16)
        age = time.time() - item.submitted_at
        print(
            f"[{'已成功 mint' if status == 1 else 'mint 失败'}] tx={item.tx_hash} nonce={item.nonce_hex} status={status} gas_used={gas_used} block={block_number} age={age:.1f}s",
            flush=True,
        )
        if status != 1:
            print("[提示] 这笔 mint 交易在链上失败了，程序会继续下一轮", flush=True)
    pending[:] = remaining


def format_hashrate(rate: float) -> str:
    units = (
        (1_000_000_000_000, "TH/s"),
        (1_000_000_000, "GH/s"),
        (1_000_000, "MH/s"),
        (1_000, "kH/s"),
    )
    for divisor, label in units:
        if rate >= divisor:
            return f"{rate / divisor:,.2f} {label}"
    return f"{rate:,.0f} H/s"


def format_restart_reason(reason: str) -> str:
    if reason == "difficulty changed":
        return "链上难度已调整，正在切换到新难度重新开始"
    if reason == "challenge changed":
        return "challenge 已变化，正在使用新 challenge 重新开始"
    if reason == "mint closed":
        return "链上 mint 已关闭，返回轮询等待"
    return reason


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parent
    dotenv = load_dotenv(root / ".env")

    parser = argparse.ArgumentParser(
        description="H98HASH hybrid miner: Python orchestrator + Rust hashing worker",
    )
    parser.add_argument("--rpc-url", default=env_value("H98HASH_RPC_URL", dotenv, DEFAULT_RPC_URL))
    parser.add_argument("--submit-rpc-url", default=env_value("H98HASH_SUBMIT_RPC_URL", dotenv))
    parser.add_argument("--address", default=env_value("H98HASH_MINER_ADDRESS", dotenv))
    parser.add_argument("--private-key", default=env_value("H98HASH_PRIVATE_KEY", dotenv))
    parser.add_argument("--backend", default=env_value("H98HASH_BACKEND", dotenv, default_backend()))
    parser.add_argument(
        "--threads",
        type=int,
        default=int(env_value("H98HASH_THREADS", dotenv, str(default_threads()))),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(env_value("H98HASH_BATCH_SIZE", dotenv, str(default_batch_size()))),
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=int(env_value("H98HASH_POLL_INTERVAL", dotenv, str(DEFAULT_POLL_INTERVAL))),
    )
    parser.add_argument("--progress-ms", type=int, default=DEFAULT_PROGRESS_MS)
    parser.add_argument("--gas-limit", type=int, default=None)
    parser.add_argument(
        "--min-priority-fee-gwei",
        type=Decimal,
        default=env_decimal("H98HASH_MIN_PRIORITY_FEE_GWEI", dotenv, DEFAULT_MIN_PRIORITY_FEE_GWEI),
    )
    parser.add_argument(
        "--max-fee-multiplier",
        type=Decimal,
        default=env_decimal("H98HASH_MAX_FEE_MULTIPLIER", dotenv, DEFAULT_MAX_FEE_MULTIPLIER),
    )
    parser.add_argument(
        "--max-pending-submissions",
        type=int,
        default=int(
            env_value(
                "H98HASH_MAX_PENDING_SUBMISSIONS",
                dotenv,
                str(DEFAULT_MAX_PENDING_SUBMISSIONS),
            )
        ),
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        default=env_flag("H98HASH_SUBMIT", dotenv, False),
        help="found nonce 后自动签名提交交易",
    )
    parser.add_argument("--once", action="store_true", help="找到一个解后退出")
    parser.add_argument("--keep-mining", dest="keep_mining", action="store_true", help="持续挖矿")
    parser.add_argument("--no-keep-mining", dest="keep_mining", action="store_false", help="提交后停止")
    parser.set_defaults(keep_mining=env_flag("H98HASH_KEEP_MINING", dotenv, True))
    parser.add_argument(
        "--wait-for-mint-open",
        dest="wait_for_mint_open",
        action="store_true",
        help="链上未开放 mint 时持续轮询等待",
    )
    parser.add_argument(
        "--no-wait-for-mint-open",
        dest="wait_for_mint_open",
        action="store_false",
        help="链上未开放 mint 时直接退出",
    )
    parser.set_defaults(wait_for_mint_open=env_flag("H98HASH_WAIT_FOR_MINT_OPEN", dotenv, True))
    return parser.parse_args()


def resolve_account(args: argparse.Namespace) -> tuple[str, LocalAccount | None]:
    if args.private_key:
        account = Account.from_key(args.private_key)
        return account.address, account
    if args.address:
        return to_checksum_address(args.address), None
    raise SystemExit("需要提供 --address 或 H98HASH_MINER_ADDRESS；自动提交则还需要 --private-key")


def main() -> int:
    args = parse_args()
    miner_address, account = resolve_account(args)
    if args.submit and account is None:
        raise SystemExit("--submit 需要同时提供 --private-key")

    root = Path(__file__).resolve().parent
    binary = ensure_worker_built(root)
    rpc = RpcClient(args.rpc_url)
    submit_rpc = RpcClient(args.submit_rpc_url or args.rpc_url)
    min_priority_fee_wei = gwei_to_wei(args.min_priority_fee_gwei)

    chain_id = rpc.chain_id()
    block_number = rpc.block_number()
    worker_backend = args.backend
    print(f"[连接成功] chain_id={chain_id} 当前区块={block_number} miner={miner_address}", flush=True)
    if chain_id != 1:
        raise SystemExit(f"当前链不是 Ethereum Mainnet（chain_id={chain_id}）")
    print(f"[算力配置] backend={worker_backend} threads={args.threads} batch_size={args.batch_size}", flush=True)

    if args.submit:
        print(
            "[自动提交] 已开启 | 持续挖矿=%s | submit-rpc=%s | 最低小费=%s gwei | max-fee倍数=%s | 最多待确认=%s"
            % (
                args.keep_mining,
                submit_rpc.rpc_url,
                args.min_priority_fee_gwei,
                args.max_fee_multiplier,
                args.max_pending_submissions,
            ),
            flush=True,
        )
    else:
        print("[自动提交] 未开启，目前只搜索不广播交易", flush=True)
    print(f"[等待策略] 未开放 mint 时{'自动轮询等待' if args.wait_for_mint_open else '直接退出'}", flush=True)

    pending_submissions: list[PendingSubmission] = []

    while True:
        drain_pending_receipts(rpc, pending_submissions)
        config = read_config(rpc)
        challenge = read_challenge(rpc, miner_address)
        print(
            "[链上状态] mint_open=%s | market_open=%s | 难度=%s bits | mint_price=%s ETH | mint_amount=%s"
            % (
                config.mint_open,
                config.market_open,
                config.difficulty_bits,
                Decimal(config.mint_price_wei) / Decimal(10**18),
                config.mint_amount,
            ),
            flush=True,
        )
        if not config.mint_open:
            if not args.wait_for_mint_open:
                print("[停止] 链上当前未开放 mint", flush=True)
                return 0
            print(f"[等待中] 链上当前未开放 mint，{args.poll_interval}s 后自动重试", flush=True)
            time.sleep(args.poll_interval)
            continue

        next_poll = time.monotonic() + args.poll_interval
        challenge_hex = "0x" + challenge.hex()

        def poll_chain() -> str | None:
            nonlocal next_poll
            if time.monotonic() < next_poll:
                return None
            next_poll = time.monotonic() + args.poll_interval

            drain_pending_receipts(rpc, pending_submissions)
            refreshed = read_config(rpc)
            refreshed_challenge = read_challenge(rpc, miner_address)
            if not refreshed.mint_open:
                return "mint closed"
            if refreshed.difficulty_bits != config.difficulty_bits:
                return "difficulty changed"
            if refreshed_challenge != challenge:
                return "challenge changed"
            return None

        try:
            result = run_worker(
                binary=binary,
                challenge_hex=challenge_hex,
                difficulty_bits=config.difficulty_bits,
                backend=worker_backend,
                threads=args.threads,
                batch_size=args.batch_size,
                progress_ms=args.progress_ms,
                poll_cb=poll_chain,
            )
        except RuntimeError as exc:
            if worker_backend == "metal":
                print(f"[警告] Metal worker 异常退出，自动切换到 CPU。\n{exc}", flush=True)
                worker_backend = "cpu"
                print(f"[算力配置] backend={worker_backend} threads={args.threads} batch_size={args.batch_size}", flush=True)
                continue
            raise

        if result["type"] == "restart":
            print(f"[重新开始] {format_restart_reason(result['reason'])}", flush=True)
            continue
        if result["type"] != "hit":
            raise RuntimeError(f"unexpected worker result: {result}")

        nonce_hex = result["nonce_hex"]
        digest_hex = result["digest_hex"]
        hashes = result["hashes"]
        elapsed_ms = result["elapsed_ms"]
        print(
            f"[找到解] nonce={nonce_hex} digest={digest_hex} 已尝试={hashes:,} 用时={elapsed_ms / 1000:.2f}s",
            flush=True,
        )

        if not args.submit:
            print("[仅搜索模式] 还没有广播交易；如需自动 mint，请开启 --submit 并提供私钥", flush=True)
            return 0

        if len(pending_submissions) >= args.max_pending_submissions:
            print(
                f"[暂不提交] 待确认交易数={len(pending_submissions)} 已达到上限={args.max_pending_submissions}，这次命中不广播，继续挖下一轮",
                flush=True,
            )
            if args.once or not args.keep_mining:
                return 0
            continue

        assert account is not None
        try:
            tx_hash = submit_solution(
                read_rpc=rpc,
                submit_rpc=submit_rpc,
                account=account,
                nonce_hex=nonce_hex,
                mint_price_wei=config.mint_price_wei,
                min_priority_fee_wei=min_priority_fee_wei,
                max_fee_multiplier=args.max_fee_multiplier,
                gas_limit_override=args.gas_limit,
            )
        except Exception as exc:
            print(f"[提交失败] nonce={nonce_hex} 错误={exc}", flush=True)
            if args.once or not args.keep_mining:
                return 1
            continue

        pending_submissions.append(
            PendingSubmission(
                tx_hash=tx_hash,
                nonce_hex=nonce_hex,
                submitted_at=time.time(),
            )
        )
        print(f"[已提交交易] tx={tx_hash} nonce={nonce_hex} 当前待确认={len(pending_submissions)}", flush=True)

        if args.once or not args.keep_mining:
            return 0
        print("[继续挖矿] 交易已发出，不等确认，直接开始下一轮", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
