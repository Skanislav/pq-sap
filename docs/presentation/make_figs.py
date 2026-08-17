"""Generate presentation figures for the EPF project summary.

Reads measured benchmark JSONs from python/benchmarks/ and renders
light-mode PNGs (dataviz reference palette) into docs/presentation/img/.
"""
import json
import os
from datetime import date

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BENCH = os.path.join(ROOT, "python", "benchmarks")
OUT = os.path.join(ROOT, "docs", "presentation", "img")
os.makedirs(OUT, exist_ok=True)

# --- palette (dataviz reference, light mode) ---
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
BLUE = "#2a78d6"      # slot 1 — ours / ML-KEM
ORANGE = "#eb6834"    # slot 2 — DKSAP baseline
BLUE_LIGHT = "#86b6ef"  # sequential step 250 (same-hue ordinal pair)

plt.rcParams.update({
    "font.family": ["Helvetica Neue", "Arial", "DejaVu Sans"],
    "text.color": INK,
    "axes.edgecolor": AXIS,
    "axes.labelcolor": INK2,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.titlecolor": INK,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "font.size": 11,
})


def style_ax(ax, ygrid=True, xgrid=False):
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    if ygrid:
        ax.grid(axis="y", color=GRID, linewidth=0.75)
    if xgrid:
        ax.grid(axis="x", color=GRID, linewidth=0.75)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), dpi=200, bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    print("wrote", name)


# ---------------------------------------------------------------- 1. scan curve
d = json.load(open(os.path.join(BENCH, "registry_curve_20260802.json")))
fig, ax = plt.subplots(figsize=(8.6, 4.4))
series = [
    ("ours/liboqs", "PQ scheme (ML-KEM-768 decaps)", BLUE),
    ("dksap", "DKSAP baseline (secp256k1 ECDH)", ORANGE),
]
for key, label, color in series:
    rows = d[key]["rows"]
    xs = [r["n"] / 1000 for r in rows]
    ys = [r["best_s"] for r in rows]
    ax.plot(xs, ys, color=color, linewidth=2, marker="o", markersize=6,
            markerfacecolor=color, markeredgecolor=SURFACE, markeredgewidth=1.5)
    fit = d[key]["fit"]
    txt = f"{label}\n{fit['slope_us_per_ann']:.1f} µs/announcement · R² = {fit['r_squared']:.4f}"
    if key == "dksap":
        ax.annotate(txt, xy=(xs[-2], ys[-2]), xytext=(30, -14), textcoords="offset points",
                    ha="left", va="top", fontsize=9.5, color=color, fontweight="bold", linespacing=1.4)
    else:
        ax.annotate(txt, xy=(xs[-1], ys[-1]), xytext=(-8, 10), textcoords="offset points",
                    ha="right", fontsize=9.5, color=color, fontweight="bold", linespacing=1.4)
ax.set_title("Scanning stays linear — measured across a 64× registry range", fontsize=12.5, loc="left", pad=14)
ax.set_xlabel("registry size (thousands of announcements)")
ax.set_ylabel("full-scan time (s)")
ax.set_xlim(0, 175)
ax.set_ylim(0, 8)
style_ax(ax)
fig.text(0.01, -0.04, "Apple M1 Max · best of 3 · includes ~N/256 view-tag false-positive derivations · registry_curve_20260802.json",
         fontsize=8, color=MUTED)
save(fig, "scan-curve.png")

# ------------------------------------------------------- 2. KEM design space
d = json.load(open(os.path.join(BENCH, "discovery_kem_20260801.json")))
rows = [r for r in d["benchmarked"]]
lit = [r for r in d["literature"] if r.get("scan80k_s")]
entries = []
for r in rows:
    entries.append((r["name"], r["level"], r["scan80k_s"], r["assumption"], False))
for r in lit:
    entries.append((r["name"], r["level"], r["scan80k_s"], r.get("assumption", ""), True))
entries.sort(key=lambda e: e[2])
fig, ax = plt.subplots(figsize=(8.6, 6.2))
ys = range(len(entries))
for i, (name, level, val, assumption, is_lit) in enumerate(entries):
    accent = name.startswith("ML-KEM")
    color = BLUE if accent else MUTED
    ax.plot([val], [i], "o", markersize=9 if accent else 7,
            markerfacecolor=SURFACE if is_lit else color,
            markeredgecolor=color, markeredgewidth=1.8, zorder=3)
    mins = val / 60
    tlabel = f"{val:,.1f} s" if val < 100 else (f"{mins:,.0f} min" if mins < 90 else f"{mins/60:,.1f} h")
    ax.annotate(tlabel, xy=(val, i), xytext=(8, -0.5), textcoords="offset points",
                fontsize=8.5, color=INK if accent else INK2, va="center",
                fontweight="bold" if accent else "normal")
labels = [f"{n}  ·  {lv}" + ("  (lit.)" if il else "") for n, lv, _, _, il in entries]
ax.set_yticks(list(ys), labels, fontsize=9.5)
for tick, (name, *_rest) in zip(ax.get_yticklabels(), entries):
    tick.set_color(INK if name.startswith("ML-KEM") else INK2)
ax.set_xscale("log")
ax.set_xlim(0.5, 3e4)
ax.invert_yaxis()
ax.set_title("Time to scan 80,000 announcements, by discovery KEM (log scale)", fontsize=12.5, loc="left", pad=14)
ax.set_xlabel("projected scan time for 80k announcements (s) — decaps × 80,000")
style_ax(ax, ygrid=False, xgrid=True)
fig.text(0.01, -0.03, "liboqs, Apple M1 Max · CSIDH from literature (hollow) · spread ≈ 3,770× · discovery_kem_20260801.json",
         fontsize=8, color=MUTED)
save(fig, "kem-design-space.png")

# ------------------------------------------------------------ 3. on-chain costs
d = json.load(open(os.path.join(BENCH, "onchain_results_20260728.json")))
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.2, 3.4), gridspec_kw={"wspace": 0.35})

pq_gas = d["announce_pq"]["measured_gas"]
dk_gas = d["announce_dksap"]["standard_total"]
ax1.barh([1, 0], [pq_gas, dk_gas], color=[BLUE, ORANGE], height=0.5)
ax1.set_yticks([1, 0], ["PQ announce\n(1,316 B calldata)", "DKSAP announce\n(292 B calldata)"], fontsize=9.5)
for y, v, note in [(1, pq_gas, "  67,580 — EIP-7623\n  calldata floor"),
                   (0, dk_gas, "  27,342")]:
    ax1.annotate(note, xy=(v, y), va="center", fontsize=9, color=INK, fontweight="bold", linespacing=1.4)
ax1.set_xlim(0, 110_000)
ax1.set_xticks([0, 25_000, 50_000, 75_000, 100_000], ["0", "25k", "50k", "75k", "100k"])
ax1.set_title("Mainnet announcement gas (measured)", fontsize=11.5, loc="left", pad=12)
ax1.set_xlabel("gas")
style_ax(ax1, ygrid=False, xgrid=True)

l2 = d["l2"]
vals = [l2["pq_calldata_l1_usd"], l2["pq_blob_l1_usd"]]
ax2.barh([1, 0], vals, color=[BLUE, BLUE_LIGHT], height=0.5)
ax2.set_yticks([1, 0], ["via calldata", "via blobs\n(EIP-4844)"], fontsize=9.5)
ax2.set_xscale("log")
ax2.set_xlim(1e-3, 60)
for y, v, lbl in [(1, vals[0], f"  ${vals[0]:.2f}"), (0, vals[1], f"  ${vals[1]:.4f}  (~320× cheaper)")]:
    ax2.annotate(lbl, xy=(v, y), va="center", fontsize=9, color=INK, fontweight="bold")
ax2.set_title("L1 data cost per PQ announcement (USD, log)", fontsize=11.5, loc="left", pad=12)
ax2.set_xlabel("marginal L1 data cost (USD)")
style_ax(ax2, ygrid=False, xgrid=True)
fig.text(0.01, -0.07, "ETH $3,200 · L1 basefee 8 gwei · blob basefee 1 gwei · onchain_results_20260728.json (model reproduces measured announce gas exactly)",
         fontsize=8, color=MUTED)
save(fig, "onchain-costs.png")

# --------------------------------------------------- 4. blinding rejection rounds
d = json.load(open(os.path.join(BENCH, "param_sweep_20260728.json")))
levels = [r["level"] for r in d]
stock = [r["rejection"]["stock_mean"] for r in d]
blind = [r["rejection"]["blinded_mean"] for r in d]
x = range(len(levels))
w = 0.32
fig, ax = plt.subplots(figsize=(7.4, 4.0))
ax.bar([i - w / 2 - 0.01 for i in x], stock, w, color=BLUE_LIGHT, label="stock ML-DSA")
ax.bar([i + w / 2 + 0.01 for i in x], blind, w, color=BLUE, label="blinded key (β′ = τ·2η)")
for i in x:
    ax.annotate(f"{stock[i]:.1f}", xy=(i - w / 2 - 0.01, stock[i]), xytext=(0, 4),
                textcoords="offset points", ha="center", fontsize=9, color=INK2)
    ax.annotate(f"{blind[i]:.1f}", xy=(i + w / 2 + 0.01, blind[i]), xytext=(0, 4),
                textcoords="offset points", ha="center", fontsize=9, color=INK, fontweight="bold")
    ax.annotate(f"{blind[i]/stock[i]:.1f}×", xy=(i + w / 2 + 0.01, blind[i] / 2), ha="center",
                fontsize=9.5, color=SURFACE, fontweight="bold")
ax.set_xticks(list(x), [f"{lv}\n{r['params']}\nη = {r['rejection']['eta']}" for lv, r in zip(levels, d)], fontsize=9)
ax.set_ylabel("mean rejection-sampling rounds per signature")
ax.set_title("Blinding penalty is non-monotone in NIST level — the L3 default pays the most",
             fontsize=12.5, loc="left", pad=14)
ax.legend(frameon=False, fontsize=9.5, loc="upper right")
style_ax(ax)
fig.text(0.01, -0.06, "N = 200 signatures per point · heavy-tailed (max observed 162 rounds) · param_sweep_20260728.json",
         fontsize=8, color=MUTED)
save(fig, "blinding-rejection.png")

# ---------------------------------------------------------------- 5. timeline
# (date, label, tier) — tiers: 0 up-near, 1 down-near, 2 up-far, 3 down-far
done = [
    (date(2026, 6, 15), "Cohort start:\nproposal, threat model,\nconstruction A/B survey", 0),
    (date(2026, 7, 8), "ePrint 2025/112 benchmark\nreproduced + key-blinding\nbibliography", 1),
    (date(2026, 7, 26), "Executable Python spec, v0 vectors,\nTS client, Sepolia receive-and-spend,\nbenchmarks + on-chain cost model", 2),
    (date(2026, 7, 31), "Lean 4 security games:\nreduction skeleton, sorry-free", 3),
    (date(2026, 8, 2), "ERC draft · KEM design-\nspace sweep · EIP-8304 PoC", 0),
]
planned = [
    (date(2026, 8, 24), "Security analysis\nwrite-up (widened-z,\nunlinkability)", 1),
    (date(2026, 9, 21), "Cost report ·\ncommunity review ·\nspec freeze", 0),
    (date(2026, 10, 19), "ERC PR to\nethereum/ERCs ·\nfinal report", 1),
    (date(2026, 11, 16), "Devcon(nect)\npresentation", 0),
]
fig, ax = plt.subplots(figsize=(10.0, 4.8))
ax.axhline(0, color=AXIS, linewidth=1.2, zorder=1)
today = date(2026, 8, 3)
ax.axvline(today, color=GRID, linewidth=1, zorder=1)
ax.annotate("today", xy=(mdates.date2num(today) + 2, -0.32), ha="left", fontsize=8, color=MUTED)

TIERS = [(26, "bottom"), (-26, "top"), (92, "bottom"), (-92, "top")]

def put(dt, label, tier, color_dot, filled, color_text):
    off, va = TIERS[tier]
    x = mdates.date2num(dt)
    ax.plot([dt], [0], "o", markersize=9,
            markerfacecolor=color_dot if filled else SURFACE,
            markeredgecolor=SURFACE if filled else color_dot,
            markeredgewidth=1.5 if filled else 1.8, zorder=3)
    if abs(off) > 40:  # far tier gets a leader line
        ax.plot([x, x], [0.12 if off > 0 else -0.12, off / 66], color=GRID, linewidth=0.9, zorder=1)
    ax.annotate(label, xy=(x, 0), xytext=(0, off), textcoords="offset points",
                ha="center", va=va, fontsize=8, color=color_text, linespacing=1.35)

for dt, label, tier in done:
    put(dt, label, tier, BLUE, True, INK2)
for dt, label, tier in planned:
    put(dt, label, tier, MUTED, False, MUTED)
ax.set_ylim(-2.3, 2.3)
ax.set_xlim(date(2026, 6, 1), date(2026, 12, 5))
ax.xaxis.set_major_locator(mdates.MonthLocator())
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
for side in ("top", "right", "left", "bottom"):
    ax.spines[side].set_visible(False)
ax.set_yticks([])
ax.tick_params(length=0, labelsize=9.5)
ax.set_title("Execution timeline — filled = shipped, hollow = remaining", fontsize=12.5, loc="left", pad=10)
save(fig, "timeline.png")

print("all figures written to", OUT)
