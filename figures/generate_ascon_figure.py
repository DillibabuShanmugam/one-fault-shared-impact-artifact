#!/usr/bin/env python3
# Generate the Ascon fault-campaign figure (tag diff distribution and instruction window) for the paper.
# Authors: Dillibabu Shanmugam and Patrick Schaumont
# Affiliation: Worcester Polytechnic Institute

import csv, os
from collections import Counter
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

CSV = "experiments/results/real_ascon_campaign.csv"
FIGS = "paper/figures"
os.makedirs(FIGS, exist_ok=True)

plt.rcParams.update({
    'font.family': 'serif', 'font.size': 12, 'font.weight': 'bold',
    'axes.labelsize': 13, 'axes.labelweight': 'bold',
    'axes.titlesize': 11, 'axes.titleweight': 'bold',
    'xtick.labelsize': 11, 'ytick.labelsize': 11, 'legend.fontsize': 10,
    'hatch.linewidth': 0.8, 'axes.linewidth': 1.0,
})


def _bold_ticks(ax):
    for lab in list(ax.get_xticklabels()) + list(ax.get_yticklabels()):
        lab.set_fontweight('bold')

rows = list(csv.DictReader(open(CSV)))[1:]

# byte-Hamming-weight distribution
bdist = Counter(int(r['diff_count']) for r in rows)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.8, 3.0))

# Left: byte diff distribution; grayscale+hatch so bars read in B&W (dark = 1 byte, hatched = 2-8 bytes, light = not useful)
keys = sorted(bdist)
vals = [bdist[k] for k in keys]

def _bar_style(k):
    if k == 1:
        return '0.20', ''          # dark, ideal
    if 2 <= k <= 8:
        return '0.55', '///'       # mid + hatch, useful
    return '0.85', ''              # light, not useful

bar_colors = [_bar_style(k)[0] for k in keys]
bar_hatch = [_bar_style(k)[1] for k in keys]
b1 = ax1.bar(keys, vals, color=bar_colors, hatch=bar_hatch,
             edgecolor='black', linewidth=1.1)
ax1.set_xlabel("Differing tag bytes")
ax1.set_ylabel("Single-bit fault traces")
ax1.set_title("Ascon Fault Diff Distribution")
ax1.set_xticks(range(0, 17, 2))
ax1.set_ylim(0, max(vals) * 1.14)
ax1.grid(True, alpha=0.3, axis='y')
# Shade + annotate the exploitable window (1-8 differing bytes).
ax1.axvspan(0.5, 8.5, alpha=0.14, color='0.4')
ax1.text(4.5, max(vals)*0.94, 'useful for DFA',
         ha='center', fontsize=10, fontweight='bold', color='black',
         style='italic')
_bold_ticks(ax1)

# Right: instr count window
instr_dist = Counter()
for r in rows:
    if int(r['diff_count']) > 0 and int(r['diff_count']) <= 8:
        instr_dist[int(r['instr'])] += 1
ix = sorted(instr_dist)
iy = [instr_dist[i] for i in ix]
ax2.plot(ix, iy, '-', color='black', linewidth=1.8)
ax2.fill_between(ix, iy, alpha=0.35, color='0.6', hatch='///',
                 edgecolor='0.4', linewidth=0.0)
ax2.set_xlabel("Retired instruction count")
ax2.set_ylabel("Useful diffs (per instr)")
ax2.set_title("Ascon Final-Permutation Window")
ax2.set_ylim(0, max(iy) * 1.12)
ax2.grid(True, alpha=0.3)
_bold_ticks(ax2)

plt.tight_layout(w_pad=2.5)
plt.savefig(f"{FIGS}/ascon_campaign.pdf", bbox_inches='tight')
plt.savefig(f"{FIGS}/ascon_campaign.png", dpi=300, bbox_inches='tight')
plt.close()
print(f"Wrote {FIGS}/ascon_campaign.pdf")
print(f"Total traces: {len(rows)}, useful (1-8 byte): {sum(bdist[k] for k in range(1,9))}")
print(f"Byte dist: {dict(sorted(bdist.items()))}")
