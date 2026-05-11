# H98HASH Local Miner

独立于现有 `HASH256` 项目的本地矿工，采用：

- Python：链上读取、签名、提交交易
- Rust：本地 `cpu` / `metal` worker 搜索 nonce

当前版本按网页前端逻辑推导本地 PoW 规则：

- 从链上读取 `challengeFor(address)` 返回的 `bytes16`
- 本地搜索 `bytes16 nonce`
- 检查 `SHA-256(challenge || nonce)` 的前 `difficulty` 位是否为 0
- 命中后提交 `mint(bytes16 nonce)`

当前默认主合约：

- `0x1E5adF70321CA28b3Ead70Eac545E6055E969e6f`

## 文件结构

- `miner.py`：Python 主控
- `rust-worker/`：Rust CPU worker
- `.env.example`：配置示例

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Rust worker 第一次运行会自动编译，也可以手动：

```bash
cd rust-worker
cargo build --release
cd ..
```

## 配置

复制配置文件：

```bash
cp .env.example .env
```

主要项：

- `H98HASH_RPC_URL`
- `H98HASH_PRIVATE_KEY`
- `H98HASH_SUBMIT=1`
- `H98HASH_BACKEND`

可选项：

- `H98HASH_THREADS`
- `H98HASH_BATCH_SIZE`
- `H98HASH_SUBMIT_RPC_URL`
- `H98HASH_MIN_PRIORITY_FEE_GWEI`
- `H98HASH_MAX_FEE_MULTIPLIER`
- `H98HASH_MAX_PENDING_SUBMISSIONS`

## 只搜索，不提交

```bash
python3 miner.py --address 0xYourMinerAddress
```

如果你在 Apple Silicon Mac 上，默认就是：

```text
H98HASH_BACKEND=metal
H98HASH_BATCH_SIZE=1048576
```

## 搜索并自动提交

```bash
python3 miner.py --submit
```

## 说明

- 当前实现是 **独立本地矿工**，不依赖网页。
- 当前 worker 支持 CPU 和 Metal GPU。
- 如果链上参数发生变化，程序会自动重新拉取 challenge 和 difficulty。
- 提交后默认立即继续下一轮，不会阻塞在等回执。
- 如果 `metal` worker 异常退出，`miner.py` 会自动回退到 `cpu`。
