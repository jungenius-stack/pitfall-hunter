#!/usr/bin/env bash
# P0 验收：逐条跑《pitfall-hunter 技能评估报告》第 5 章「验收（可执行）」列
# 用法：
#   bash _verify/verify.sh                          # 验开发区副本
#   S=<原脚本> SK=<原SKILL> bash _verify/verify.sh   # 反向对照（应大面积 FAIL）
cd "$(dirname "$0")" || exit 1
S=${S:-../scripts/audit_session.py}
SK=${SK:-../SKILL.md}
CARDS=${CARDS:-../references/pitfall-cards.md}
L5=${L5:-../scripts/l5_blocks.py}
CS=${CS:-../scripts/check_agents_sync.py}
REAL=${REAL:-$HOME/.workbuddy/projects/Users-m1-Downloads-shj/ea45b2fe-6a4f-4b7e-acab-6845e1842641.jsonl}
HAS_REAL=0; [ -f "$REAL" ] && HAS_REAL=1
FX=_fixtures
mkdir -p "$FX"
python3 - "$FX" <<'PY'
import csv, os, sys
d = sys.argv[1]
def w(n, g):
    with open(os.path.join(d, n), 'w', newline='') as f:
        csv.writer(f).writerows(g)
z = [[0] * 10 for _ in range(10)]
w('ref.csv', z)
a = [r[:] for r in z]
for y in range(3, 6):
    for x in range(3, 6):
        a[y][x] = 1
w('block3.csv', a)
b = [r[:] for r in z]; b[2][2] = 1; w('single.csv', b)
c = [r[:] for r in z]; c[2][2] = 1; c[3][3] = 1; w('diag.csv', c)
w('wrong.csv', [[0] * 9 for _ in range(9)])
with open(os.path.join(d, 'canary.jsonl'), 'w', encoding='utf-8') as f:
    f.write('{"type":"message","role":"user","content":[{"type":"input_text","text":'
            '"<system-reminder>上轮埋了 AUDIT-CANARY-abc123 的探针</system-reminder>你好"}],"timestamp":1}\n')
with open(os.path.join(d, 'slow.py'), 'w') as f:
    f.write('import time\ntime.sleep(3)\n')
PY
FX_ABS=$(pwd)/$FX
PASS=0; FAIL=0; SKIP=0
ok() { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
no() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
verdict() { if [ "$1" = "1" ]; then ok "$2"; else no "$2"; fi; }
skip() { SKIP=$((SKIP+1)); printf '  SKIP  %s\n' "$1"; }

echo "被测脚本：$S"
[ "$HAS_REAL" = 0 ] && echo "WARN: 未找到本机会话，9 项会话类检查将跳过（REAL=<session.jsonl> 可启用）"
true

echo "== P0-1 --expect-hash 失败路径 =="
out=$(python3 "$S" empty.jsonl --repro gen.py --expect-hash deadbeef 2>&1); rc=$?
[ "$rc" = 2 ] && printf '%s' "$out" | grep -q 'MISMATCH' && verdict 1 "错哈希 → MISMATCH + exit 2" || { verdict 0 "错哈希 → MISMATCH + exit 2 (rc=$rc)"; printf '%s\n' "$out" | tail -4; }
out=$(python3 "$S" empty.jsonl --repro gen.py --expect-hash 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881 2>&1); rc=$?
[ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'MATCH' && verdict 1 "正哈希 → MATCH + exit 0" || verdict 0 "正哈希 → MATCH + exit 0 (rc=$rc)"
out=$(python3 "$S" empty.jsonl --repro gen.py 2>&1); rc=$?
[ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'SKIPPED: 未提供期望哈希' && verdict 1 "无期望哈希 → SKIPPED 明示 + exit 0" || verdict 0 "无期望哈希 → SKIPPED 明示 (rc=$rc)"

echo "== P0-2 领域词不再写死 =="
out=$(python3 "$S" mini_finance.jsonl 2>&1)
if printf '%s' "$out" | grep -q 'WARN: 未指定领域词' && printf '%s' "$out" | grep -q 'injected ' && printf '%s' "$out" | grep -q 'user(later)'; then
  verdict 1 "无 --domain → WARN + 仍列分组"
else
  verdict 0 "无 --domain → WARN + 仍列分组"; printf '%s\n' "$out" | sed -n '/L4/,/L3/p' | head -8
fi
out=$(python3 "$S" mini_finance.jsonl --domain 财务,报表 2>&1)
if ! printf '%s' "$out" | grep -q 'WARN: 未指定领域词' && printf '%s' "$out" | grep -q '财务' && printf '%s' "$out" | grep -q '报表'; then
  verdict 1 "传 --domain 财务,报表 → 不 WARN + 按新词统计"
else
  verdict 0 "传 --domain 财务,报表 → 不 WARN + 新词命中"; printf '%s\n' "$out" | grep -A1 '关键词'
fi

if [ "$HAS_REAL" = 1 ]; then
  echo "== P0-3 注入 / 本人发言 / 后续轮次分离 =="
  out=$(python3 "$S" "$REAL" 2>&1)
  line=$(printf '%s\n' "$out" | grep '切分效果')
  echo "  $line"
  printf '%s' "$line" | grep -q '189 条 user 消息 → injected 183 / user 1 / user(later) 187' && verdict 1 "189 条 → 183/1/187（另 1 条纯注入）" || verdict 0 "189 条 → 183/1/187"
  printf '%s' "$out" | grep -q '注入块 14217 + 本人发言 8240 = 22457' && verdict 1 "首条守恒 14217+8240=22457" || { verdict 0 "首条守恒 14217+8240=22457"; printf '%s\n' "$out" | grep '校验'; }

else
  for _ in 1 2; do
    skip "P0-3 需要本机真实会话（已跳过）"
  done
fi

echo "== P0-4 解析失败必须报数 =="
out=$(python3 "$S" bad.jsonl 2>&1)
printf '%s' "$out" | grep -q 'DROPPED: 2 行解析失败' && verdict 1 "2 行坏 JSON → DROPPED: 2" || { verdict 0 "2 行坏 JSON → DROPPED: 2"; printf '%s\n' "$out" | head -2; }
out=$(python3 "$S" mini.jsonl 2>&1)
printf '%s' "$out" | grep -q 'DROPPED: 0 行解析失败' && verdict 1 "干净文件 → DROPPED: 0" || verdict 0 "干净文件 → DROPPED: 0"

if [ "$HAS_REAL" = 1 ]; then
  echo "== P0-5 路径默认脱敏 =="
  default_out=$(python3 "$S" "$REAL" 2>&1)
  if printf '%s' "$default_out" | grep -q '/Users/m1/'; then verdict 0 "默认输出不含 /Users/m1/"; printf '%s\n' "$default_out" | grep '/Users/m1/' | head -3; else verdict 1 "默认输出不含 /Users/m1/"; fi
  printf '%s' "$default_out" | grep -q '…/Users-m1-Downloads-shj/ea45b2fe' && verdict 1 "会话路径形如 …/项目目录/会话.jsonl" || { verdict 0 "会话路径形如 …/项目目录/…"; printf '%s\n' "$default_out" | head -1; }
  out=$(python3 "$S" "$REAL" --no-redact 2>&1)
  if printf '%s' "$out" | grep -q '/Users/m1/.workbuddy/projects/' && ! printf '%s' "$default_out" | grep -q '/Users/m1/'; then
    verdict 1 "--no-redact 关闭脱敏（默认确实开着）"
  else
    verdict 0 "--no-redact 关闭脱敏（默认确实开着）"
  fi

else
  for _ in 1 2 3; do
    skip "P0-5 需要本机真实会话（已跳过）"
  done
fi

echo "== P0-6 SKILL.md 标注 L2/L6 未实现 =="
n=$(grep -E 'L2 ·|L6 ·' "$SK" | grep -c '人工')
[ "$n" = 2 ] && verdict 1 "SKILL.md L2/L6 标题含「人工」（$n/2）" || verdict 0 "SKILL.md L2/L6 标题含「人工」（$n/2）"
n=$(grep -c '脚本未实现' "$SK")
[ "$n" -ge 2 ] && verdict 1 "SKILL.md「脚本未实现」>=2（$n ）" || verdict 0 "SKILL.md「脚本未实现」>=2（$n ）"

echo "== P0-7 --selftest =="
out=$(python3 "$S" --selftest 2>&1); rc=$?
self_ok=0
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'SELFTEST: 3/3 passed'; then self_ok=1; fi
verdict "$self_ok" "--selftest → 3/3 passed + exit 0（rc=$rc ）"
sed 's/^    return .PASS. if actual in exp else .MISMATCH.$/    return "PASS"/' "$S" > /tmp/_mut_audit.py
out=$(python3 /tmp/_mut_audit.py --selftest 2>&1); rc=$?
if [ "$self_ok" = 1 ] && [ "$rc" != 0 ] && ! printf '%s' "$out" | grep -q '3/3 passed'; then
  verdict 1 "判定函数换常量 → 报数失败 + exit $rc"
else
  verdict 0 "判定函数换常量 → 应报失败（base_ok=$self_ok rc=$rc ）"
fi
rm -f /tmp/_mut_audit.py
python3 -S -B "$S" --selftest >/dev/null 2>&1 && verdict 1 "python3 -S -B 可跑（无第三方依赖）" || verdict 0 "python3 -S -B 可跑"

echo "== P0-8 S1 改名 =="
n=$(grep -c 'L5 · 可疑模式命中' "$S"); [ "$n" = 0 ] && verdict 1 "旧标题已移除" || verdict 0 "旧标题仍在（$n ）"
n=$(grep -c 'S1' "$S"); [ "$n" -ge 1 ] && verdict 1 "S1 标记存在（$n ）" || verdict 0 "S1 标记缺失"

echo "== P1-1 canary 主动探针 =="
out=$(python3 "$S" "$FX/canary.jsonl" --canary AUDIT-CANARY-abc123 2>&1)
printf '%s' "$out" | grep -q 'ALERT: canary 被复述' && verdict 1 "canary 命中 → ALERT" || { verdict 0 "canary 命中 → ALERT"; printf '%s\n' "$out" | grep -i canary; }
out=$(python3 "$S" "$FX/canary.jsonl" --canary AUDIT-CANARY-zzz 2>&1)
printf '%s' "$out" | grep -q '未出现（0 次）' && verdict 1 "canary 未命中 → 0 次" || { verdict 0 "canary 未命中 → 0 次"; printf '%s\n' "$out" | grep -i canary; }
out=$(python3 "$S" "$FX/canary.jsonl" 2>&1)
printf '%s' "$out" | grep -q 'WARN: 未提供 --canary' && verdict 1 "未提供 canary → WARN 明示" || verdict 0 "未提供 canary → WARN 明示"

if [ "$HAS_REAL" = 1 ]; then
  echo "== P1-2 证据层完成度 / 指标 / 结论句 =="
  out=$(python3 "$S" "$REAL" --domain 地图,坐标 --repro gen.py --expect-hash 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881 2>&1)
  printf '%s' "$out" | grep -q '证据层完成度：3 / 6（L1、L3、L4 有物证；L2、L5、L6 无）' && verdict 1 "真实会话 → 3 / 6（L1、L3、L4）" || { verdict 0 "真实会话 → 3 / 6"; printf '%s\n' "$out" | grep '证据层'; }
  printf '%s' "$out" | grep -q '判定覆盖率：1/1' && verdict 1 "判定覆盖率 1/1" || { verdict 0 "判定覆盖率 1/1"; printf '%s\n' "$out" | grep '判定覆盖'; }
  printf '%s' "$out" | grep -q '不可复现占比' && verdict 1 "不可复现占比有分母口径" || verdict 0 "不可复现占比缺失"
  printf '%s' "$out" | grep -q '未经效度检验' && verdict 1 "指标标注「未经效度检验」" || verdict 0 "指标标注「未经效度检验」"
  printf '%s' "$out" | grep -q '结论：排除了运行时外部读取，未排除编译期硬编码' && verdict 1 "结论句已降级" || { verdict 0 "结论句已降级"; printf '%s\n' "$out" | grep '结论'; }

else
  for _ in 1 2 3 4 5; do
    skip "P1-2 需要本机真实会话（已跳过）"
  done
fi

echo "== P1-3 --json =="
if python3 "$S" "$FX/canary.jsonl" --domain 探针 --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); assert {"session","l4","l3","s1","l1","metrics","conclusion","options"} <= set(d); assert d["metrics"]["evidence_layers"].endswith("/6")'; then
  verdict 1 "--json 可解析且字段齐"
else
  verdict 0 "--json 可解析且字段齐"
fi

echo "== P1-4 SKILL.md 口径 =="
grep -q '未排除编译期硬编码' "$SK" && verdict 1 "L1 写入「未排除编译期硬编码」" || verdict 0 "L1 写入「未排除编译期硬编码」"
if grep -q '作弊在物理上不可能' "$SK"; then
  grep -n '作弊在物理上不可能' "$SK" | grep -q '不要写成' && verdict 1 "「物理上不可能」只作反例出现" || verdict 0 "「物理上不可能」仍被当断言"
else
  verdict 1 "「物理上不可能」已删除"
fi
grep -q '块周长 ÷ 块面积' "$SK" && verdict 1 "L5 给出无量纲比" || verdict 0 "L5 给出无量纲比"
grep -Eq '需按分辨率标定|必须按当前分辨率标定' "$SK" && verdict 1 "L5 标注需按分辨率标定" || verdict 0 "L5 标注需按分辨率标定"
if grep -q '1–4 格' "$SK"; then
  grep -n '1–4 格' "$SK" | grep -q '不要再用' && verdict 1 "「1–4 格」只作禁用说明" || verdict 0 "「1–4 格」仍作阈值"
else
  verdict 1 "绝对阈值已移除"
fi
grep -q '标准误' "$SK" && grep -q '只报相关性' "$SK" && grep -Eq 'n ?≥ ?3|n≥3' "$SK" && verdict 1 "L6 三条纪律齐" || verdict 0 "L6 三条纪律齐"
grep -q '失效条件' "$SK" && grep -q '提示可疑，需人工核对' "$SK" && verdict 1 "L2 失效条件 + 结论降级" || verdict 0 "L2 失效条件 + 结论降级"

echo "== P1-5 卡片库元数据 =="
n=$(grep -c '> 元数据：date' "$CARDS"); [ "$n" -ge 17 ] && verdict 1 "card metadata lines >= 17: $n" || verdict 0 "card metadata lines: got $n (want >= 17)"
n=$(grep -c 'invalid-when' "$CARDS"); [ "$n" -ge 17 ] && verdict 1 "invalid-when fields: $n" || verdict 0 "invalid-when fields: $n"
n=$(grep -c '^## CI-002 ·' "$CARDS"); [ "$n" = 1 ] && verdict 1 "CI-002 has standalone card" || verdict 0 "CI-002 standalone card missing"
grep -q '不写「作弊在物理上不可能」' "$CARDS" && verdict 1 "QA-001 claim downgraded" || verdict 0 "QA-001 claim not downgraded"

echo "== P1-6 l5_blocks 无量纲统计 =="
out=$(python3 "$L5" "$FX/block3.csv" "$FX/ref.csv" 2>&1)
printf '%s' "$out" | grep -q '块周长 ÷ 块面积：max 1.333' && verdict 1 "3x3 block: perimeter/area 1.333" || { verdict 0 "3x3 block: perimeter/area 1.333"; printf '%s\n' "$out" | head -5; }
out=$(python3 "$L5" "$FX/single.csv" "$FX/ref.csv" 2>&1)
printf '%s' "$out" | grep -q 'max 4.000' && verdict 1 "single cell: ratio 4.000" || verdict 0 "single cell: ratio 4.000"
out=$(python3 "$L5" "$FX/diag.csv" "$FX/ref.csv" 2>&1)
printf '%s' "$out" | grep -q '连通块：1 个' && verdict 1 "diagonal pair joins into 1 block (8-neighbour)" || verdict 0 "diagonal pair joins"
out=$(python3 "$L5" "$FX/wrong.csv" "$FX/ref.csv" 2>&1); rc=$?
printf '%s' "$out" | grep -q 'ERROR: 两份栅格尺寸不一致' && [ "$rc" = 1 ] && verdict 1 "shape mismatch -> clean error rc=1" || verdict 0 "shape mismatch clean error"

echo "== P2-1 check_agents_sync =="
printf 'x' > "$FX/a1"; printf 'x' > "$FX/a2"; printf 'y' > "$FX/a3"
python3 "$CS" "$FX/a1" "$FX/a2" >/dev/null 2>&1; [ $? = 0 ] && verdict 1 "identical -> rc 0" || verdict 0 "identical -> rc 0"
python3 "$CS" "$FX/a1" "$FX/a3" >/dev/null 2>&1; [ $? = 1 ] && verdict 1 "different -> rc 1" || verdict 0 "different -> rc 1"
out=$(python3 "$CS" "$FX/a1" "$FX/nope" 2>&1); rc=$?
printf '%s' "$out" | grep -q 'MISSING:' && [ "$rc" = 2 ] && verdict 1 "missing -> MISSING + rc 2" || verdict 0 "missing -> MISSING + rc 2"

echo "== P2-2 复现超时 =="
out=$(python3 "$S" empty.jsonl --repro "$FX/slow.py" --timeout 1 2>&1); rc=$?
printf '%s' "$out" | grep -q 'TIMEOUT: 脚本超过 1 秒' && [ "$rc" = 2 ] && verdict 1 "timeout -> TIMEOUT + rc 2" || { verdict 0 "timeout -> TIMEOUT + rc 2"; printf '%s\n' "$out" | tail -3; }

echo "== P2-3 工程卫生 =="
n=$(grep -c 'EMPTY_RESPONSE|EMPTY_RESPONSE' "$S"); [ "$n" = 0 ] && verdict 1 "SUSPECT regex deduped" || verdict 0 "SUSPECT regex still duplicated: $n"
grep -A2 'def sha256' "$S" | grep -q 'with open' && verdict 1 "sha256 uses with open" || verdict 0 "sha256 file handle"

echo "== P2-4 抽样可复现 =="
o1=$(python3 "$S" mini.jsonl --domain 财务 --sample 0 --seed 7 2>&1 | grep 'SAMPLE')
o2=$(python3 "$S" mini.jsonl --domain 财务 --sample 0 --seed 7 2>&1 | grep 'SAMPLE')
[ -n "$o1" ] && [ "$o1" = "$o2" ] && verdict 1 "same seed -> same sample (reproducible)" || verdict 0 "same seed -> same sample"
out=$(python3 "$S" mini.jsonl --domain 财务 --sample 0 --seed 7 2>&1)
printf '%s' "$out" | grep -q 'SKIPPED: 抽样跳过' && verdict 1 "sample=0 skips optional layers" || verdict 0 "sample=0 skips optional layers"
printf '%s' "$out" | grep -q '未经实验验证' && verdict 1 "sample premise flagged unvalidated" || verdict 0 "sample premise flagged"

echo
echo "结果：PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" = 0 ] || exit 1
