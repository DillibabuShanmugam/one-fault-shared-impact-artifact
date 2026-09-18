#!/usr/bin/env python3
# Generate the SIMT amplification figure (lanes struck per fault, per-column coverage) from real_simt_campaign.csv.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute
import csv, os
from collections import Counter
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

CSV  = "simx_aes/real_simt_campaign.csv"
FIGS = "paper/figures"
os.makedirs(FIGS, exist_ok=True)

plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 12,
    'font.weight': 'bold',
    'axes.labelsize': 13,
    'axes.labelweight': 'bold',
    'axes.titlesize': 11,
    'axes.titleweight': 'bold',
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'legend.fontsize': 10,
    'hatch.linewidth': 0.8,
    'axes.linewidth': 1.0,
})

# Grayscale fills + hatches so bars are distinguishable in B&W print.
GRAYS = ['0.90', '0.72', '0.55', '0.38', '0.18']
HATCHES = ['///', 'xxx', '...', '\\\\\\', 'ooo']


def _bold_ticks(ax):
    for lab in list(ax.get_xticklabels()) + list(ax.get_yticklabels()):
        lab.set_fontweight('bold')

rows = list(csv.DictReader(open(CSV)))[1:]  # skip golden

n_fired_dist = Counter()
clean_4lane_4byte = []
amplification_per_instr = []
col_per_instr = []
for r in rows:
    n_fired = int(r['n_fired'])
    n_fired_dist[n_fired] += 1
    diff_counts = [int(r[f'diff_count_{i}']) for i in range(4)]
    cols = [int(r[f'col_{i}']) for i in range(4)]
    if n_fired == 4 and all(d == 4 for d in diff_counts):
        clean_4lane_4byte.append(r)
        if all(c == cols[0] for c in cols):
            col_per_instr.append(cols[0])
    amplification_per_instr.append(n_fired)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.8, 3.0))

counts = sorted(n_fired_dist.items())
keys = [k for k, _ in counts]
vals = [v for _, v in counts]
bars = ax1.bar(keys, vals, color=[GRAYS[k] for k in keys],
               hatch=[HATCHES[k] for k in keys],
               edgecolor='black', linewidth=1.1)
for b, v in zip(bars, vals):
    ax1.text(b.get_x() + b.get_width()/2, b.get_height() + max(vals)*0.02,
             str(v), ha='center', fontsize=9, fontweight='bold')
ax1.set_xlabel('SIMT lanes corrupted by one fault')
ax1.set_ylabel('Fault injections')
ax1.set_title('SIMT Amplification Distribution')
ax1.set_xticks(keys)
ax1.set_ylim(0, max(vals) * 1.14)
ax1.grid(True, alpha=0.3, axis='y')
_bold_ticks(ax1)

col_counts = Counter(col_per_instr)
cols_x = [0, 1, 2, 3]
col_vals = [col_counts.get(c, 0) for c in cols_x]
ax2.bar(cols_x, col_vals, color=[GRAYS[c] for c in cols_x],
        hatch=[HATCHES[c] for c in cols_x],
        edgecolor='black', linewidth=1.1)
for c, v in zip(cols_x, col_vals):
    ax2.text(c, v + (max(col_vals) if col_vals else 1)*0.02, str(v),
             ha='center', fontsize=9, fontweight='bold')
ax2.set_xlabel('DFA fault column')
ax2.set_ylabel('4-lane fault injections')
ax2.set_title('Per-Column Coverage')
ax2.set_xticks(cols_x)
ax2.set_ylim(0, (max(col_vals) if col_vals else 1) * 1.15)
ax2.grid(True, alpha=0.3, axis='y')
_bold_ticks(ax2)

plt.tight_layout(w_pad=2.5)
plt.savefig(f"{FIGS}/simt_amplification.pdf", bbox_inches='tight')
plt.savefig(f"{FIGS}/simt_amplification.png", dpi=300, bbox_inches='tight')
plt.close()
print(f"  simt_amplification.pdf")
print(f"  Total injections in window: {len(rows)}")
print(f"  4-lane fires (4-byte each): {len(clean_4lane_4byte)}")
print(f"  Per-column distribution: {dict(col_counts)}")
print(f"  CTs/injection (avg amplification): {sum(amplification_per_instr)/len(rows):.2f}")
