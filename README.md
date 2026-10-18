# pitfall-hunter（踩坑专家 · 取证版）

给 Agent 的**会话日志**做取证式体检：查开工前注入了什么、调用了哪些工具、产物能不能隔离重跑复现，最后给一个**有边界**的结论。

> ⚠️ 这不是那套 118 张卡的 `pitfall-expert`。分工不同：
> - `pitfall-expert`：任务**开始前**扫风险（「我要动这个，会踩什么坑」）
> - `pitfall-hunter`（本仓库）：出问题**之后**做归因取证（「它是不是作弊/被污染/降智」）

## 能回答什么 / 不能回答什么

**能**

- 这次产物是不是该脚本的确定性函数？（隔离重跑 + 哈希比对，错配退出码 2）
- 开工前注入了多少东西、什么来源？（`injected` / `user` / `user(later)` 分开计，带守恒校验）
- 上一轮埋的 canary 有没有被复述回来？（记忆污染主动探针）
- 工具调用里读过哪些题目外的文件？（默认脱敏，只留路径末两段）
- 这次审计到底有几层拿到了物证？（证据层完成度 k / 6）

**不能**

- **不能证明「作弊」。** 哈希一致只证明「自洽」，不证明「独立」——编译期硬编码、数据内联、照抄现成产物都不在它的证据范围内。结论固定写成「排除了运行时外部读取，未排除编译期硬编码」。
- **L2（脚本静态审计）、L5（误差形态）、L6（跨运行相关性）没有自动化**，是人工步骤，脚本只给辅助统计。
- 三个量化指标**未经效度检验**，只适合同一工具前后对比，别当绝对分数。

## 安装

```bash
# 任意 Agent 的 skills 目录皆可；WorkBuddy AI 的默认位置：
cp -R . ~/.workbuddy-ai/skills/pitfall-hunter
```

## 用法

```bash
S=~/.workbuddy-ai/skills/pitfall-hunter/scripts/audit_session.py

# 1. 体检一份会话（自动识别 dsh / codex / workbuddy 三种格式）
python3 $S <会话.jsonl> --domain 地图,坐标

# 2. 复现比对：期望哈希给错 → MISMATCH + 退出码 2
python3 $S <会话.jsonl> --repro <产物脚本> --expect-hash <sha256>

# 3. 机器可读
python3 $S <会话.jsonl> --domain 地图 --json

# 4. 自检
python3 $S --selftest            # SELFTEST: 3/3 passed

# 5. 规则文件分叉检查（CI-001）
python3 scripts/check_agents_sync.py

# 6. 误差块的无量纲形态（L5 人工判读用，不给判决）
python3 scripts/l5_blocks.py pred.csv ref.csv
```

Codex 的 `rollout-*.jsonl.zst` 与 dsh 的 `session.v4.jsonl.zstd` 需先解压：

```bash
python3 - <<'PY'
import zstandard
with open('session.v4.jsonl.zstd','rb') as f, open('session.jsonl','wb') as g:
    zstandard.ZstdDecompressor().copy_stream(f, g)
PY
```

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 正常（含 `SKIPPED`：未给期望哈希，未做判定） |
| 1 | 用法错误 / 自检失败 |
| 2 | 审计发现不一致或无法判定（`MISMATCH` / `TIMEOUT` / 脚本缺失） |

## 测试

```bash
cd tests && bash verify.sh
# 本机有真实会话：52 项全跑
# 没有会话文件：42 项 + 10 SKIP（会话类检查自动跳过，不会假失败）
```

测试自带负向对照：同一套检查对 0.1 基线（未版本化的原始脚本）是 **1 通过 / 51 失败**——证明这些断言不是摆设。

## 版本

`0.2.0`（2026-10-18）。首个带版本号的发布：8 条「会说错话」修复 + P1/P2 增强。详见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

未声明。原技能目录没有附许可证，正式开源前请先定一个。
