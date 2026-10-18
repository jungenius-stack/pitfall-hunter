#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pitfall-hunter · 会话半自动审计

用法：
    python3 audit_session.py <session.jsonl> [--domain 关键词1,关键词2,...] [--canary TOKEN]
    python3 audit_session.py <session.jsonl> --repro <产物脚本> [--expect-hash <sha256>,...]
    python3 audit_session.py <session.jsonl> --json
    python3 audit_session.py --selftest

    --timeout 秒    复现超时（默认 600）
    --sample 0.5    只跑一部分可选检查项（要配 --seed 才能复现；该做法本身未经实验验证）
    --seed 42       抽样种子
    --no-redact     打印完整路径（默认只留路径末两段）

支持三种会话格式（自动识别）：dsh / codex / workbuddy
输出：L3 工具调用、L4 注入上下文、S1 可疑模式、L1 可复现性、审计摘要
退出码：0 正常；1 用法错误或自检失败；2 审计发现不一致 / 无法判定

口径说明（重要）：
  · L1 的哈希一致只证明「产物是脚本的确定性函数」，即排除了**运行时**外部读取；
    它不排除编译期硬编码、数据内联、抄袭已存在的产物。结论不得写成「作弊不可能」。
  · L2（脚本静态审计）、L5（误差形态）、L6（跨运行相关性）没有自动实现，
    审计摘要里的「证据层完成度」会把它们计为「无物证」。
  · 摘要里的三个指标是自定义口径，未经效度检验，只用于同一工具前后对比。
"""
import json, os, sys, re, hashlib, collections, subprocess, tempfile, shutil, random

REDACT = True          # P0-5：默认脱敏，--no-redact 关闭
HUMAN = True           # --json 时关闭人类可读输出
TOOL_VERSION = '0.2.0'
SYSTEM_RE = re.compile(r'<system-reminder[^>]*>.*?</system-reminder>', re.S)


def redact(p):
    """只保留路径末两段（项目目录 + 文件名），丢掉 /Users/<用户名>/ 之类前缀。"""
    if not REDACT:
        return str(p)
    s = str(p).split('/')
    return '…/' + '/'.join(s[-2:]) if len(s) > 2 else str(p)


def say(*a):
    if HUMAN:
        print(*a)


# ---------------------------------------------------------------- 格式识别
def load(path):
    """返回 (格式, 事件列表, 解析失败行数)。解析失败必须计数，不能静默丢。"""
    ev = []
    bad = 0
    for line in open(path, encoding='utf-8', errors='ignore'):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            bad += 1
            continue
        if not isinstance(e, dict):
            bad += 1
            continue
        ev.append(e)
    kinds = collections.Counter(e.get('type') for e in ev)
    if 'session' in kinds and 'step/start' in kinds:
        return 'dsh', ev, bad
    if 'session_meta' in kinds and 'response_item' in kinds:
        return 'codex', ev, bad
    if 'message' in kinds and 'timestamp' in (ev[0] if ev else {}):
        return 'workbuddy', ev, bad
    return 'unknown', ev, bad


# ---------------------------------------------------------------- L4 注入上下文
# P0-2：不再内置领域词。词表必须由 --domain 显式给出——自动从会话自身抽词是循环论证，
# 且两次审计的词表不同就不可比。缺省时只列分组、不做统计，并明确 WARN。
DOMAIN_DEFAULT = []


def audit_injections(kind, ev, domain, canary=None):
    head = ('injected = 系统注入块，user = 本人发言，user(later) = 后续轮次'
            if kind == 'workbuddy' else '按来源标签分组')
    say(f'\n=== L4 · 注入上下文（{head}）===')
    items = []
    n_msgs = 0          # workbuddy：user 消息总数，用于校验切分是否守恒
    first_pair = None   # workbuddy：首条消息的（注入块长度, 本人发言长度）
    if kind == 'dsh':
        for e in ev:
            if e.get('type') != 'user/message':
                continue
            d = e.get('data') or {}
            src = d.get('source') or {}
            s = ''.join(c.get('text', '') for c in (d.get('content') or []) if isinstance(c, dict))
            items.append((src.get('kind') or 'user', s))
    elif kind == 'codex':
        for e in ev:
            if e.get('type') == 'session_meta':
                p = e.get('payload') or {}
                bi = p.get('base_instructions')
                if bi:
                    items.append(('base_instructions', bi.get('text', '') if isinstance(bi, dict) else str(bi)))
            if e.get('type') == 'response_item':
                p = e.get('payload') or {}
                if p.get('type') == 'message' and p.get('role') in ('developer', 'user'):
                    s = ''.join(c.get('text', '') for c in (p.get('content') or []) if isinstance(c, dict))
                    tag = 'developer' if p.get('role') == 'developer' else 'user-injected'
                    if 'AGENTS.md' in s:
                        tag = 'AGENTS.md'
                    items.append((tag, s))
    elif kind == 'workbuddy':
        # P0-3：<system-reminder> 块是系统注入，块外才是本人发言。混成一个 user 会把
        # 用户自己说的字符也算进「注入量」，导致归因错位。
        first = True
        for e in ev:
            if e.get('type') != 'message' or e.get('role') != 'user':
                continue
            n_msgs += 1
            c = e.get('content')
            s = ''
            if isinstance(c, list):
                for p in c:
                    if isinstance(p, dict) and p.get('type') in ('input_text', 'text'):
                        s += p.get('text', '')
            blocks = SYSTEM_RE.findall(s)
            blk = '\n'.join(blocks)
            rest = SYSTEM_RE.sub('', s)
            if first:
                first_pair = (len(blk), len(rest))
            if blk:
                items.append(('injected', blk))
            if rest:
                items.append(('user', rest) if first else ('user(later)', rest))
            first = False

    if not domain:
        say('  WARN: 未指定领域词，关键词命中不做统计（用 --domain 关键词1,关键词2 指定）')

    agg = {}
    for tag, s in items:
        if not s:
            continue
        a = agg.setdefault(tag, [0, 0])
        a[0] += len(s)
        a[1] += 1
    for tag, (chars, n) in agg.items():
        say(f'  {tag:<12}{chars:>7} 字符（{n} 条）')
    total = sum(v[0] for v in agg.values())
    say(f'  {"合计":<12}{total:>7} 字符')

    if kind == 'workbuddy' and agg:
        u_n = agg.get('user', [0, 0])[1]
        l_n = agg.get('user(later)', [0, 0])[1]
        i_n = agg.get('injected', [0, 0])[1]
        extra = f'（另 {n_msgs - u_n - l_n} 条只含注入块、无本人文字）' if n_msgs > u_n + l_n else ''
        say(f'  切分效果：{n_msgs} 条 user 消息 → injected {i_n} / user {u_n} / user(later) {l_n}{extra}')
        if first_pair:
            bl, rl = first_pair
            say(f'  首条消息校验：注入块 {bl} + 本人发言 {rl} = {bl + rl} 字符')

    # 关键词只统计开工前注入与首条本人发言；user(later) 是用户自己的后续指令，
    # 不是污染源，算进去会把正常对话量当成注入量（dsh/codex 的注入标签按原样统计）。
    kw = collections.Counter()
    for tag, s in items:
        if tag == 'user(later)' or not s:
            continue
        for k in (domain or []):
            n = s.count(k)
            if n:
                kw[k] += n
    if domain:
        say(f'  关键词命中：{dict(kw)}（不含 user(later)）')

    # P1：canary 主动探针。上一轮埋 AUDIT-CANARY-<uuid>，本轮看它是否被复述回来。
    canary_hits = 0
    canary_where = []
    if canary:
        for tag, s in items:
            n = s.count(canary)
            if n:
                canary_hits += n
                canary_where.append(tag)
        if canary_hits:
            say(f'  ALERT: canary 被复述 {canary_hits} 次（出现在 {sorted(set(canary_where))}），疑似记忆污染')
        else:
            say(f'  canary：{canary} 未出现（0 次）')
    else:
        say('  WARN: 未提供 --canary，本轮无主动探针，无法排除记忆污染')

    say('  提示：命中 ≠ 污染。需进一步比对本次产物与上次产物的具体数值是否相同（答案级转移）。')
    return {
        'groups': {t: {'chars': v[0], 'count': v[1]} for t, v in agg.items()},
        'total_chars': total,
        'messages': n_msgs,
        'first_message': {'injected': first_pair[0], 'user': first_pair[1]} if first_pair else None,
        'keyword_hits': dict(kw),
        'canary': {'provided': bool(canary), 'hits': canary_hits, 'where': sorted(set(canary_where))},
    }


# ---------------------------------------------------------------- L3 工具调用
def audit_tools(kind, ev):
    say('\n=== L3 · 工具调用路径 ===')
    calls = []
    if kind == 'dsh':
        for e in ev:
            if e.get('type') != 'tool/call':
                continue
            d = e.get('data') or {}
            try:
                a = json.loads(d.get('arguments') or '{}')
            except Exception:
                a = {}
            tgt = a.get('file_path') or a.get('path') or a.get('command') or a.get('name') or ''
            calls.append((d.get('name'), str(tgt)))
    elif kind == 'codex':
        for e in ev:
            if e.get('type') != 'response_item':
                continue
            p = e.get('payload') or {}
            if p.get('type') == 'function_call':
                try:
                    a = json.loads(p.get('arguments') or '{}')
                except Exception:
                    a = {}
                calls.append((p.get('name'), str(a.get('cmd') or a.get('command') or '')))
            # 注意：写文件是 custom_tool_call，不是 function_call
            if p.get('type') == 'custom_tool_call':
                calls.append((p.get('name') + ' (custom)', str(p.get('input'))[:120]))
    elif kind == 'workbuddy':
        for e in ev:
            if e.get('type') == 'function_call':
                calls.append((e.get('name'), str(e.get('arguments') or '')[:120]))

    cnt = collections.Counter(n for n, _ in calls)
    say(f'  共 {len(calls)} 次；分布 {dict(cnt)}')
    reads = [t for n, t in calls if n in ('read', 'Read', 'read_file') or 'cat ' in t or 'view_image' in n or 'read_image' in n]
    say(f'  读取类目标（{len(reads)} 个，已脱敏）：')
    for t in reads[:40]:
        say(f'    · {redact(t)[:130]}')
    return {
        'calls': len(calls),
        'distribution': dict(cnt),
        'read_targets': [redact(t)[:130] for t in reads[:40]],
        'skipped': False,
    }


# ---------------------------------------------------------------- S1 可疑模式
# P0-8：这不是 L5（L5 是误差形态分析）。同名不同物会让报告引用错层，改称 S1。
SUSPECT = [
    (r'does not declare image input', 'CFG-002 配置缺 input 声明 → 拒图'),
    (r'EMPTY_RESPONSE', '网关空流重试'),
    (r'stream idle timeout|Stream timeout', '流超时'),
    (r'queue\.full|queue\.waiting', '网关排队/限流'),
    (r'exceed quota', '配额超限'),
    (r'AssertionError', '脚本断言失败（正常，说明自检有效）'),
    (r'SELF INTERSECTION|self_intersection', '多边形自交（几何坑）'),
]


def audit_suspect(kind, ev):
    say('\n=== 可疑模式扫描（S1，不属于 L5）===')
    txt = ''
    for e in ev:
        txt += json.dumps(e, ensure_ascii=False) + '\n'
    hits = []
    for pat, desc in SUSPECT:
        n = len(re.findall(pat, txt))
        if n:
            say(f'  {n:>4} 次  {desc}')
            hits.append({'count': n, 'desc': desc})
    return {'matches': hits, 'skipped': False}


# ---------------------------------------------------------------- L1 可复现性
def sha256(p):
    with open(p, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def _verdict(actual, expected):
    """把「哈希比对」这一个判断抽成纯函数，供 --selftest 断言。

    expected 可为 None / 单个哈希 / 哈希列表。返回 PASS | MISMATCH | SKIPPED。
    """
    if not expected:
        return 'SKIPPED'
    exp = {expected} if isinstance(expected, str) else set(expected)
    return 'PASS' if actual in exp else 'MISMATCH'


def audit_repro(script, expect, timeout=600):
    """隔离重跑并比对哈希。返回结构化结果，status ∈ PASS/MISMATCH/SKIPPED/TIMEOUT/MISSING。"""
    say('\n=== L1 · 隔离重跑可复现性 ===')
    out = {'status': 'MISSING', 'script': redact(script), 'exit_code': None, 'produced': []}
    if not os.path.exists(script):
        say(f'  脚本不存在：{redact(script)}')
        return out
    tmp = tempfile.mkdtemp(prefix='audit_iso_')
    shutil.copy2(script, tmp)
    say(f'  隔离目录：{tmp}（只含脚本一个文件）')
    try:
        r = subprocess.run([sys.executable, '-S', '-B', os.path.basename(script)],
                           cwd=tmp, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        say(f'  TIMEOUT: 脚本超过 {timeout} 秒未结束，未取得产物')
        out['status'] = 'TIMEOUT'
        return out
    out['exit_code'] = r.returncode
    say(f'  退出码 {r.returncode}')
    if r.stdout.strip():
        say('  stdout 末 5 行：')
        for l in r.stdout.strip().split('\n')[-5:]:
            say(f'    {l[:160]}')
    if r.returncode != 0 and r.stderr.strip():
        say('  stderr 末 5 行：')
        for l in r.stderr.strip().split('\n')[-5:]:
            say(f'    {l[:160]}')
    produced = sorted(f for f in os.listdir(tmp) if f != os.path.basename(script))
    say(f'  产出 {len(produced)} 个文件：')
    if not expect:
        say('  哈希判定：SKIPPED: 未提供期望哈希（--expect-hash）')
    status = 'SKIPPED'
    for f in produced:
        h = sha256(os.path.join(tmp, f))
        v = _verdict(h, expect)
        out['produced'].append({'file': f, 'sha256': h, 'verdict': v})
        suffix = ''
        if v == 'PASS':
            suffix = '   MATCH <-- 与期望哈希一致'
            status = 'PASS' if status != 'MISMATCH' else status
        elif v == 'MISMATCH':
            suffix = '   MISMATCH <-- 与期望哈希不一致'
            status = 'MISMATCH'
        say(f'    {h}  {f}{suffix}')
    if expect and not produced:
        # 给了期望哈希却没有任何产出，同样不能静默放行
        say('  MISMATCH: 给了 --expect-hash 但脚本没有产出任何文件')
        status = 'MISMATCH'
    out['status'] = status
    return out


# ---------------------------------------------------------------- 审计摘要
def summarize(l1, l3, l4):
    """证据层完成度：只数「真的跑出了物证」的层。L2/L5/L6 未实现，永远不算。"""
    layers = []
    if l1.get('status') in ('PASS', 'MISMATCH'):
        layers.append('L1')
    if l3.get('calls', 0) > 0:
        layers.append('L3')
    if l4.get('groups'):
        layers.append('L4')
    missing = [x for x in ('L1', 'L2', 'L3', 'L4', 'L5', 'L6') if x not in layers]
    produced = l1.get('produced') or []
    verdicts = [p for p in produced if p['verdict'] in ('PASS', 'MISMATCH')]
    mismatches = [p for p in produced if p['verdict'] == 'MISMATCH']
    return {
        'layers_done': len(layers),
        'layers': layers,
        'layers_missing': missing,
        'outputs': len(produced),
        'verdicts': len(verdicts),
        'mismatches': len(mismatches),
    }


def conclusion_text(status):
    return {
        'PASS': '排除了运行时外部读取，未排除编译期硬编码',
        'MISMATCH': '产物与期望哈希不一致：脚本读取了外部状态，或产物被事后改动',
        'SKIPPED': '未提供期望哈希，未做复现，外部读取无法排除',
        'TIMEOUT': '复现超时，未取得物证',
        'MISSING': '产物脚本不存在，未做复现',
    }.get(status, '未做复现')


def _truthy_fail(l1):
    return l1.get('status') in ('MISMATCH', 'TIMEOUT', 'MISSING')


# ---------------------------------------------------------------- 自检
def _selftest():
    """用 CI-005 的判据审自己：判定函数必须能被断言卡住，且损坏时要报数退出非 0。"""
    H = '2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881'
    checks = [
        ('同哈希 → PASS', _verdict(H, H) == 'PASS'),
        ('错哈希 → MISMATCH', _verdict(H, 'deadbeef') == 'MISMATCH'),
        ('无期望哈希 → SKIPPED', _verdict(H, None) == 'SKIPPED'),
    ]
    ok = sum(1 for _, passed in checks if passed)
    for name, passed in checks:
        print(f'  {"ok  " if passed else "FAIL"} {name}')
    print(f'SELFTEST: {ok}/{len(checks)} passed')
    return 0 if ok == len(checks) else 1


# ---------------------------------------------------------------- main
def _num(s, cast, default):
    try:
        return cast(s)
    except Exception:
        print(f'WARN: 参数不是合法数字 {s!r}，用默认 {default}', file=sys.stderr)
        return default


def main():
    global REDACT, HUMAN
    argv = sys.argv[1:]
    if '--selftest' in argv:
        sys.exit(_selftest())
    if not argv:
        print(__doc__)
        sys.exit(1)
    path = argv[0]
    domain = None
    canary = None
    repro = None
    expect = []
    timeout = 600
    sample = 1.0
    seed = 0
    as_json = False
    args = argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--domain' and i + 1 < len(args):
            domain = args[i + 1].split(',')
            i += 2
        elif a == '--canary' and i + 1 < len(args):
            canary = args[i + 1]
            i += 2
        elif a == '--repro' and i + 1 < len(args):
            repro = args[i + 1]
            i += 2
        elif a == '--expect-hash' and i + 1 < len(args):
            expect += args[i + 1].split(',')
            i += 2
        elif a == '--timeout' and i + 1 < len(args):
            timeout = _num(args[i + 1], int, 600)
            i += 2
        elif a == '--sample' and i + 1 < len(args):
            sample = _num(args[i + 1], float, 1.0)
            i += 2
        elif a == '--seed' and i + 1 < len(args):
            seed = _num(args[i + 1], int, 0)
            i += 2
        elif a == '--json':
            as_json = True
            HUMAN = False
            i += 1
        elif a == '--redact':
            REDACT = True
            i += 1
        elif a == '--no-redact':
            REDACT = False
            i += 1
        else:
            print(f'WARN: 忽略未知参数 {a}', file=sys.stderr)
            i += 1

    kind, ev, bad = load(path)
    say(f'会话文件：{redact(path)}')
    say(f'格式识别：{kind}    事件数：{len(ev)}    DROPPED: {bad} 行解析失败')

    plan = {'l3': True, 's1': True}
    if sample < 1.0:
        rnd = random.Random(seed)
        plan = {k: rnd.random() < sample for k in plan}
        skipped = [k.upper() for k, run in plan.items() if not run]
        say(f'SAMPLE: 抽样比例 {sample:g}，seed={seed}；跳过 {"、".join(skipped) if skipped else "无"}')
        say('WARN: --sample 会跳过检查项，结论不能与全量审计直接比较（该做法本身未经实验验证）')

    l4 = audit_injections(kind, ev, domain, canary)
    if plan['l3']:
        l3 = audit_tools(kind, ev)
    else:
        say('\n=== L3 · 工具调用路径 ===\n  SKIPPED: 抽样跳过')
        l3 = {'calls': 0, 'distribution': {}, 'read_targets': [], 'skipped': True}
    if plan['s1']:
        s1 = audit_suspect(kind, ev)
    else:
        say('\n=== 可疑模式扫描（S1，不属于 L5）===\n  SKIPPED: 抽样跳过')
        s1 = {'matches': [], 'skipped': True}

    l1 = {'status': 'NOT_RUN', 'script': repro, 'produced': []}
    if repro:
        l1 = audit_repro(repro, expect, timeout)

    s = summarize(l1, l3, l4)
    concl = conclusion_text(l1.get('status'))
    say('\n=== 审计摘要 ===')
    miss = '、'.join(s['layers_missing'])
    if s['layers']:
        say(f'  证据层完成度：{s["layers_done"]} / 6（{"、".join(s["layers"])} 有物证；{miss} 无）')
    else:
        say(f'  证据层完成度：0 / 6（本次没有任何一层取得物证；{miss} 无）')
    ratio = f'{s["mismatches"]}/{s["verdicts"]}' if s['verdicts'] else 'n/a'
    say(f'  判定覆盖率：{s["verdicts"]}/{s["outputs"]} 个产出有哈希判定；'
        f'不一致 {s["mismatches"]} 个（不可复现占比 {ratio}）')
    say('  指标口径：自定义，未经效度检验，只用于同一工具前后对比')
    say(f'  结论：{concl}')
    say('\n完成。判定时请对照 references/pitfall-cards.md，并如实标注「无法验证」项。')

    report = {
        'tool': 'pitfall-hunter/audit_session.py',
        'version': TOOL_VERSION,
        'session': {'path': redact(path), 'format': kind, 'events': len(ev), 'dropped_lines': bad},
        'l4': l4,
        'l3': l3,
        's1': s1,
        'l1': l1,
        'metrics': {
            'evidence_layers': f'{s["layers_done"]}/6',
            'layers_with_evidence': s['layers'],
            'layers_missing': s['layers_missing'],
            'outputs': s['outputs'],
            'verdicts': s['verdicts'],
            'mismatches': s['mismatches'],
            'unreproducible_ratio': ratio,
        },
        'conclusion': concl,
        'options': {
            'domain': domain,
            'canary_provided': bool(canary),
            'sample': sample,
            'seed': seed,
            'timeout': timeout,
        },
    }
    if as_json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write('\n')

    sys.exit(2 if _truthy_fail(l1) else 0)


if __name__ == '__main__':
    main()
