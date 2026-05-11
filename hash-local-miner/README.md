# HASH256 Hybrid Miner for macOS

Python 负责链上交互和控制流程，Rust 负责高速搜索 `keccak256(challenge || nonce)`。

这个程序是按 `hash256.org` 前端当前公开的合约接口写的：

- 合约地址：`0xAC7b5d06fa1e77D08aea40d46cB7C5923A87A0cc`
- 关键接口：`genesisState()`、`miningState()`、`getChallenge(address)`、`mine(uint256)`

## 特性

- 支持 macOS 本地运行
- Python + Rust 混合架构
- 支持 `cpu` / `metal` 两种 worker 后端
- 在 Apple Silicon Mac 上默认使用 `metal` GPU 后端
- 默认安全模式：只搜索，不自动提交交易
- 提供私钥后可自动签名并广播 `mine(nonce)`
- 算力速率自动显示成 `MH/s`、`GH/s` 等更直观单位
- 提交交易后立即继续下一轮，不阻塞在等回执
- 支持单独的提交 RPC，适合接私有 relay / Protect RPC
- 轮询链上 epoch / difficulty，变化后会自动重启 worker，避免继续算过期 challenge

## 目录

- `miner.py`：Python 主控 CLI
- `rust-worker/`：Rust 高速哈希 worker
- `.env.example`：环境变量示例

## 准备

建议先创建虚拟环境：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Rust worker 第一次运行会自动编译；也可以手动先编译：

```bash
cd rust-worker
cargo build --release
cd ..
```

## 配置

复制一份 `.env.example` 为项目根目录的 `.env`，程序会自动读取。至少要准备：

- `HASH256_RPC_URL`
- `HASH256_MINER_ADDRESS`
- `HASH256_BACKEND`

如果要自动提交交易，再额外准备：

- `HASH256_PRIVATE_KEY`
- `HASH256_SUBMIT=1`
- `HASH256_SUBMIT_RPC_URL`

建议为自动提交专门使用一个单独钱包，不要把主钱包私钥直接塞进脚本环境。

优先级是：

- 命令行参数
- 当前 shell 里的环境变量
- 项目根目录 `.env`

## 只搜索，不提交

```bash
cp .env.example .env
python3 miner.py \
  --rpc-url https://ethereum-rpc.publicnode.com \
  --address 0xYourMinerAddress
```

如果你在 Apple Silicon Mac 上，当前默认就是 GPU；也可以显式这样写：

```text
HASH256_BACKEND=metal
HASH256_BATCH_SIZE=1048576
```

## 搜索并自动提交

```bash
cp .env.example .env
python3 miner.py --submit
```

把 `.env` 里的 `HASH256_PRIVATE_KEY` 改成你的值后，有私钥时地址会自动从私钥推导，不需要再额外传 `--address`。
如果你想完全靠 `.env` 自动提交，也可以把 `HASH256_SUBMIT=1` 写进去，然后直接运行 `python3 miner.py`。

如果你想更不容易被公开 mempool 里的机器人抢到，可以把提交 RPC 设成私有 relay，例如：

```text
HASH256_SUBMIT_RPC_URL=https://rpc.flashbots.net/fast
```

## 常用参数

- `--threads 7`：Rust worker 线程数
- `--backend cpu|metal`：切换 CPU 或 Metal GPU 后端
- `--batch-size 1048576`：每批次提交给 worker 的 nonce 数量
- `--poll-interval 12`：每多少秒检查一次 challenge / difficulty 是否变化
- `--submit`：自动签名并广播 mint 交易
- `--no-keep-mining`：提交一笔后停止
- `--once`：成功提交一笔后退出
- `--gas-limit 300000`：手动覆盖 gas limit
- `--submit-rpc-url ...`：单独指定发交易 RPC
- `--min-priority-fee-gwei 0.5`：最小 priority fee
- `--max-fee-multiplier 3`：`maxFeePerGas = baseFee * multiplier + priorityFee`
- `--max-pending-submissions 1`：单钱包最多同时挂几笔待确认交易

## 注意事项

- 这个项目当前链上如果还没开放挖矿，脚本会直接退出。
- challenge 是地址绑定的；搜索和提交必须对应同一个 miner 地址。
- 脚本会在 epoch 或 difficulty 改变时自动重启 worker，避免用陈旧 challenge 提交无效 nonce。
- 自动提交模式下，回执检查在后台进行，不会因为等待确认而中断挖矿。
- 默认会限制单钱包只有 1 笔 pending 提交，这通常比堆很多同 nonce 序列交易更不容易把自己卡住。
- `metal` 后端目前只在 macOS 上可用；如果在受限环境里跑不到 GPU，可以先回退到 `cpu`。
- 如果 `metal` worker 异常退出，`miner.py` 现在会自动回退到 `cpu` 并继续运行。
- 纯 Python 并不负责高速哈希；性能主要来自 Rust worker。

## 预期输出

运行时你会看到类似：

```text
[rpc] chain_id=1 block=...
[mode] auto-submit=on keep-mining=True
[genesis] minted=... complete=True
[state] era=1 reward=100 HASH difficulty=0x...
[worker] 1,234,567 hashes | 8.45 MH/s | 3.0s
[hit] nonce=0x... digest=0x...
[tx] submitted 0x... nonce=0x... pending=1
[loop] continuing immediately after submit
[receipt] tx=0x... nonce=0x... status=1 gas_used=...
```
