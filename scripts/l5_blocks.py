#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L5 误差形态的**无量纲**统计 —— 只给指标，不下判决。

用法：
    python3 l5_blocks.py pred.csv ref.csv [--tol 0]

两份 CSV 必须同尺寸，元素为数字（0/1 或类别值）。逐格比较得错误格，再做 8 邻域连通块。

为什么要无量纲：原来的经验阈值是「块极小（1–4 格）」，它随分辨率漂移——
同一块海岸线在 90×180 和 180×360 下格数会差 4 倍。所以这里只输出比值：

    · 错误率 = 错误格 ÷ 总格数
    · 连通块数
    · 最大块面积 ÷ 错误格数
    · 块面积 ÷ 栅格面积（max / mean）
    · 块周长 ÷ 块面积（max / mean，越大越细长）
    · 单格块占比

**阈值必须按你的分辨率标定一次**（用已知的「手绘」和「数据降采样」样本各跑一遍），
本脚本不判断「手绘 / 降采样」，也不给通过线 —— 结论由人下。
"""
import csv
import sys


def read_grid(path):
    with open(path, newline='', encoding='utf-8') as f:
        return [[float(c) for c in row if str(c).strip() != ''] for row in csv.reader(f) if row]


def error_mask(pred, ref, tol):
    if len(pred) != len(ref) or any(len(a) != len(b) for a, b in zip(pred, ref)):
        raise ValueError('两份栅格尺寸不一致')
    return [[abs(pred[y][x] - ref[y][x]) > tol for x in range(len(pred[y]))] for y in range(len(pred))]


def blocks(mask):
    """8 邻域连通块：返回 [(面积, 周长), ...]。"""
    h, w = len(mask), len(mask[0]) if mask else 0
    seen = [[False] * w for _ in range(h)]
    out = []
    for y0 in range(h):
        for x0 in range(w):
            if not mask[y0][x0] or seen[y0][x0]:
                continue
            stack = [(y0, x0)]
            seen[y0][x0] = True
            area = perim = 0
            while stack:
                y, x = stack.pop()
                area += 1
                for dy, dx in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    ny, nx = y + dy, x + dx
                    if 0 <= ny < h and 0 <= nx < w and mask[ny][nx]:
                        continue
                    perim += 1
                for dy in (-1, 0, 1):
                    for dx in (-1, 0, 1):
                        ny, nx = y + dy, x + dx
                        if 0 <= ny < h and 0 <= nx < w and mask[ny][nx] and not seen[ny][nx]:
                            seen[ny][nx] = True
                            stack.append((ny, nx))
            out.append((area, perim))
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    tol = 0.0
    if '--tol' in sys.argv[1:]:
        tol = float(sys.argv[sys.argv.index('--tol') + 1])
    if len(args) < 2:
        print(__doc__)
        return 1
    pred, ref = read_grid(args[0]), read_grid(args[1])
    try:
        mask = error_mask(pred, ref, tol)
    except ValueError as e:
        print(f'ERROR: {e}')
        return 1
    h = len(mask)
    w = len(mask[0]) if mask else 0
    cells = h * w
    err = sum(sum(1 for v in row if v) for row in mask)
    bs = blocks(mask)

    print(f'栅格：{h} × {w} = {cells} 格；错误 {err} 格（{err / cells:.2%}）')
    if not bs:
        print('无错误格：L5 无可分析对象')
        return 0
    areas = sorted(a for a, _ in bs)
    per_area = [p / a for a, p in bs]
    print(f'连通块：{len(bs)} 个')
    print(f'最大块面积 ÷ 错误格数：{areas[-1] / err:.3f}')
    print(f'块面积 ÷ 栅格面积：max {areas[-1] / cells:.5f}；mean {sum(areas) / len(areas) / cells:.5f}')
    print(f'块周长 ÷ 块面积：max {max(per_area):.3f}；mean {sum(per_area) / len(per_area):.3f}')
    print(f'单格块占比：{sum(1 for a in areas if a == 1) / len(areas):.2%}')
    print('提醒：以上均为无量纲比；阈值需按当前分辨率标定一次（见 SKILL.md L5），本脚本不下判决。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
