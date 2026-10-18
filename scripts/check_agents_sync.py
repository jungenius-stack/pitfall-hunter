#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""比对两份 AGENTS.md 的 sha256 —— CI-001（规则分叉）的防回归检查。

用法：
    python3 check_agents_sync.py
    python3 check_agents_sync.py <A> <B>

默认比对 ~/AGENTS.md 与 ~/.codex/AGENTS.md。两份内容不同 → 同一模型换外壳行为分叉。

退出码：0 一致；1 不一致；2 文件缺失
"""
import hashlib
import os
import sys


def sha256(p):
    with open(p, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    a = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser('~/AGENTS.md')
    b = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser('~/.codex/AGENTS.md')

    missing = [p for p in (a, b) if not os.path.exists(p)]
    for p in missing:
        print(f'MISSING: {p}')
    if missing:
        return 2

    ha, hb = sha256(a), sha256(b)
    print(f'A {ha}  {a}')
    print(f'B {hb}  {b}')
    if ha == hb:
        print('OK: 两份规则文件一致')
        return 0
    print('MISMATCH: 两份规则文件不一致 —— 同一模型会因读到不同规则而行为分叉（CI-001）')
    print('修复：确定唯一权威版本，跑一次同步脚本（例如 ~/AGENTS-sync.sh），再复查本脚本')
    return 1


if __name__ == '__main__':
    sys.exit(main())
