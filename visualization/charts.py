import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from collections import Counter
from datetime import datetime

# ── Dark theme for all charts ────────────────────────────────
DARK = {
    "bg":      "#0d1117",
    "axes_bg": "#161b22",
    "text":    "#c9d1d9",
    "grid":    "#21262d",
    "bar1":    "#4d9eff",
    "bar2":    "#00ff88",
    "accent":  "#a371f7",
    "warn":    "#ffa500",
    "danger":  "#ff4444",
}

def _apply_theme(fig, ax):
    fig.patch.set_facecolor(DARK["bg"])
    ax.set_facecolor(DARK["axes_bg"])
    ax.tick_params(colors=DARK["text"], labelsize=9)
    ax.xaxis.label.set_color(DARK["text"])
    ax.yaxis.label.set_color(DARK["text"])
    ax.title.set_color(DARK["text"])
    for spine in ax.spines.values():
        spine.set_edgecolor(DARK["grid"])
    ax.yaxis.grid(True, color=DARK["grid"], linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)


# ── Top IPs ──────────────────────────────────────────────────
def plot_top_ips(data):
    if not data:
        return
    ips    = [x[0] for x in data]
    counts = [x[1] for x in data]

    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_theme(fig, ax)

    colors = [DARK["danger"] if c == max(counts) else DARK["bar1"] for c in counts]
    bars = ax.barh(ips, counts, color=colors, height=0.6, edgecolor="none")

    for bar, cnt in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                str(cnt), va="center", color=DARK["text"], fontsize=9)

    ax.set_title("Top Active Source IP Addresses", fontsize=13, pad=14, fontweight="bold")
    ax.set_xlabel("Packet Count")
    ax.invert_yaxis()
    plt.tight_layout()
    plt.show()


# ── Top Ports ────────────────────────────────────────────────
def plot_top_ports(data):
    if not data:
        return
    ports  = [str(x[0]) for x in data]
    counts = [x[1] for x in data]

    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_theme(fig, ax)

    bars = ax.bar(ports, counts, color=DARK["accent"], width=0.6, edgecolor="none")

    for bar, cnt in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(counts) * 0.01,
                str(cnt), ha="center", color=DARK["text"], fontsize=9)

    ax.set_title("Top Destination Ports", fontsize=13, pad=14, fontweight="bold")
    ax.set_xlabel("Port")
    ax.set_ylabel("Packet Count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


# ── Protocol distribution (pie) ──────────────────────────────
def plot_protocol_pie(proto_counts: dict):
    labels  = [k for k, v in proto_counts.items() if v > 0]
    values  = [v for v in proto_counts.values()    if v > 0]
    if not values:
        return

    palette = [DARK["bar1"], DARK["bar2"], DARK["warn"]]
    explode = [0.04] * len(labels)

    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor(DARK["bg"])
    ax.set_facecolor(DARK["bg"])

    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        colors=palette[:len(labels)],
        explode=explode,
        startangle=140,
        wedgeprops={"edgecolor": DARK["bg"], "linewidth": 2},
    )
    for t in texts:
        t.set_color(DARK["text"])
        t.set_fontsize(11)
    for at in autotexts:
        at.set_color(DARK["bg"])
        at.set_fontsize(10)
        at.set_fontweight("bold")

    ax.set_title("Protocol Distribution", fontsize=13, pad=14,
                 fontweight="bold", color=DARK["text"])
    plt.tight_layout()
    plt.show()


# ── Packets over time ────────────────────────────────────────
def plot_traffic_timeline(packets):
    if not packets:
        return

    # Count by second bucket
    bucket: Counter = Counter()
    for p in packets:
        bucket[p.get("time", "00:00:00")] += 1

    times  = sorted(bucket.keys())
    counts = [bucket[t] for t in times]

    fig, ax = plt.subplots(figsize=(12, 5))
    _apply_theme(fig, ax)

    ax.fill_between(range(len(times)), counts,
                    color=DARK["bar2"], alpha=0.2)
    ax.plot(range(len(times)), counts,
            color=DARK["bar2"], linewidth=2)

    step = max(1, len(times) // 10)
    ax.set_xticks(range(0, len(times), step))
    ax.set_xticklabels([times[i] for i in range(0, len(times), step)],
                       rotation=45, ha="right", fontsize=8)

    ax.set_title("Packet Volume Over Time", fontsize=13, pad=14, fontweight="bold")
    ax.set_xlabel("Time")
    ax.set_ylabel("Packets / second")
    plt.tight_layout()
    plt.show()