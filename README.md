# Local Miner Workspace

这个仓库现在拆成两个并列项目：

- `hash-local-miner/`
  对应 `HASH256` 的本地矿工，支持 `cpu` / `metal`
- `h98hash-local-miner/`
  对应 `H98HASH` 的本地矿工，支持 `cpu` / `metal`

## 建议用法

进入具体项目目录后再运行：

```bash
cd hash-local-miner
```

或：

```bash
cd h98hash-local-miner
```

共享虚拟环境时，可以在子项目中这样启用：

```bash
source ../.venv/bin/activate
```

每个子项目里都有各自的：

- `README.md`
- `.env.example`
- `miner.py`
- `rust-worker/`
