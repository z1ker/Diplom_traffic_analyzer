"""
Модуль для візуалізації статистики мережевого трафіку.
Використовує matplotlib для побудови графіків у світлій, сучасній темі.
"""

from collections import Counter
import matplotlib.pyplot as plt

# Сучасна світла тема для графіків
LIGHT_THEME = {
    "bg": "#F3F4F6",  # Світло-сірий фон
    "axes_bg": "#FFFFFF",  # Білий фон графіків
    "text": "#374151",  # Темно-сірий текст
    "grid": "#E5E7EB",  # Світла сітка
    "bar1": "#3B82F6",  # Синій (Primary)
    "bar2": "#10B981",  # Зелений (Success)
    "accent": "#8B5CF6",  # Фіолетовий (Accent)
    "warn": "#F59E0B",  # Жовтий (Warning)
    "danger": "#EF4444",  # Червоний (Danger)
}


def _apply_theme(fig, ax):
    """Застосовує світлу тему до об'єктів Figure та Axes."""
    fig.patch.set_facecolor(LIGHT_THEME["bg"])
    ax.set_facecolor(LIGHT_THEME["axes_bg"])
    ax.tick_params(colors=LIGHT_THEME["text"], labelsize=9)
    ax.xaxis.label.set_color(LIGHT_THEME["text"])
    ax.yaxis.label.set_color(LIGHT_THEME["text"])
    ax.title.set_color(LIGHT_THEME["text"])

    for spine in ax.spines.values():
        spine.set_edgecolor(LIGHT_THEME["grid"])

    ax.yaxis.grid(True, color=LIGHT_THEME["grid"], linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)


def plot_top_ips(data: list):
    """Будує горизонтальну гістограму найактивніших IP-адрес."""
    if not data:
        return

    ips = [x[0] for x in data]
    counts = [x[1] for x in data]

    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_theme(fig, ax)

    colors = [LIGHT_THEME["danger"] if c == max(counts) else LIGHT_THEME["bar1"] for c in counts]
    bars = ax.barh(ips, counts, color=colors, height=0.6, edgecolor="none")

    for bar, cnt in zip(bars, counts):
        ax.text(
            bar.get_width() + max(counts) * 0.01,
            bar.get_y() + bar.get_height() / 2,
            str(cnt),
            va="center",
            color=LIGHT_THEME["text"],
            fontsize=9
        )

    ax.set_title("Top Active Source IP Addresses", fontsize=13, pad=14, fontweight="bold")
    ax.set_xlabel("Packet Count")
    ax.invert_yaxis()
    plt.tight_layout()
    plt.show()


def plot_top_ports(data: list):
    """Будує гістограму найбільш активних портів призначення."""
    if not data:
        return

    ports = [str(x[0]) for x in data]
    counts = [x[1] for x in data]

    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_theme(fig, ax)

    bars = ax.bar(ports, counts, color=LIGHT_THEME["accent"], width=0.6, edgecolor="none")

    for bar, cnt in zip(bars, counts):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(counts) * 0.01,
            str(cnt),
            ha="center",
            color=LIGHT_THEME["text"],
            fontsize=9
        )

    ax.set_title("Top Destination Ports", fontsize=13, pad=14, fontweight="bold")
    ax.set_xlabel("Port")
    ax.set_ylabel("Packet Count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def plot_protocol_pie(proto_counts: dict):
    """Будує кругову діаграму розподілу протоколів."""
    labels = [k for k, v in proto_counts.items() if v > 0]
    values = [v for v in proto_counts.values() if v > 0]
    if not values:
        return

    palette = [LIGHT_THEME["bar1"], LIGHT_THEME["bar2"], LIGHT_THEME["warn"]]
    explode = [0.04] * len(labels)

    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor(LIGHT_THEME["bg"])
    ax.set_facecolor(LIGHT_THEME["bg"])

    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        colors=palette[:len(labels)],
        explode=explode,
        startangle=140,
        wedgeprops={"edgecolor": LIGHT_THEME["bg"], "linewidth": 2},
    )
    for text_element in texts:
        text_element.set_color(LIGHT_THEME["text"])
        text_element.set_fontsize(11)
    for autotext in autotexts:
        autotext.set_color("#FFFFFF")
        autotext.set_fontsize(10)
        autotext.set_fontweight("bold")

    ax.set_title("Protocol Distribution", fontsize=13, pad=14, fontweight="bold", color=LIGHT_THEME["text"])
    plt.tight_layout()
    plt.show()


def plot_traffic_timeline(packets: list):
    """Будує лінійний графік об'єму трафіку в часі."""
    if not packets:
        return

    bucket = Counter()
    for packet in packets:
        bucket[packet.get("time", "00:00:00")] += 1

    times = sorted(bucket.keys())
    counts = [bucket[t] for t in times]

    fig, ax = plt.subplots(figsize=(12, 5))
    _apply_theme(fig, ax)

    ax.fill_between(range(len(times)), counts, color=LIGHT_THEME["bar1"], alpha=0.15)
    ax.plot(range(len(times)), counts, color=LIGHT_THEME["bar1"], linewidth=2)

    step = max(1, len(times) // 10)
    ax.set_xticks(range(0, len(times), step))
    ax.set_xticklabels(
        [times[i] for i in range(0, len(times), step)],
        rotation=45,
        ha="right",
        fontsize=8
    )

    ax.set_title("Packet Volume Over Time", fontsize=13, pad=14, fontweight="bold")
    ax.set_xlabel("Time")
    ax.set_ylabel("Packets / second")
    plt.tight_layout()
    plt.show()