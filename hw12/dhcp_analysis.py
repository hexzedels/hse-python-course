import json
import csv
from datetime import datetime
from pathlib import Path

import pyshark
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

DIR   = Path(__file__).parent
PCAP  = DIR / "dhcp.pcapng"
OUT_CSV  = DIR / "dhcp_artifacts.csv"
OUT_JSON = DIR / "dhcp_artifacts.json"
OUT_PLOT = DIR / "dhcp_visualization.png"

DHCP_TYPES = {
    "1": "Discover",
    "2": "Offer",
    "3": "Request",
    "4": "Decline",
    "5": "ACK",
    "6": "NAK",
    "7": "Release",
    "8": "Inform",
}


print("=" * 60)
print("Этап 1 — Загрузка сетевого дампа")
print("=" * 60)
print(f"Файл: {PCAP}")

cap = pyshark.FileCapture(str(PCAP))
packets = list(cap)
cap.close()
print(f"Загружено пакетов: {len(packets)}\n")

print("=" * 60)
print("Этап 2 — Извлечение DHCP-артефактов")
print("=" * 60)

def safe(layer, field, default="N/A"):
    try:
        return str(getattr(layer, field))
    except AttributeError:
        return default

artifacts = []

for pkt in packets:
    if not hasattr(pkt, "dhcp"):
        continue

    dhcp = pkt.dhcp
    ip   = pkt.ip if hasattr(pkt, "ip") else None
    eth  = pkt.eth if hasattr(pkt, "eth") else None

    msg_code = safe(dhcp, "option_dhcp")
    msg_name = DHCP_TYPES.get(msg_code, f"Type-{msg_code}")

    record = {
        "frame":       int(pkt.number),
        "timestamp":   str(pkt.sniff_time),
        "dhcp_type":   msg_name,
        "src_ip":      safe(ip,  "src")         if ip  else "N/A",
        "dst_ip":      safe(ip,  "dst")         if ip  else "N/A",
        "src_mac":     safe(eth, "src")         if eth else "N/A",
        "dst_mac":     safe(eth, "dst")         if eth else "N/A",
        "client_mac":  safe(dhcp, "hw_mac_addr"),
        "client_ip":   safe(dhcp, "ip_client"),
        "offered_ip":  safe(dhcp, "ip_your"),
        "server_ip":   safe(dhcp, "ip_server"),
        "server_id":   safe(dhcp, "option_dhcp_server_id"),
        "subnet_mask": safe(dhcp, "option_subnet_mask"),
        "lease_time_s": safe(dhcp, "option_ip_address_lease_time"),
        "renewal_s":   safe(dhcp, "option_renewal_time_value"),
        "rebind_s":    safe(dhcp, "option_rebinding_time_value"),
        "req_ip":      safe(dhcp, "option_requested_ip_address"),
        "transaction_id": safe(dhcp, "id"),
    }
    artifacts.append(record)

    print(f"  Frame {record['frame']:>2} | {record['timestamp']} | "
          f"{record['dhcp_type']:<10} | "
          f"src={record['src_ip']:<15} dst={record['dst_ip']:<15} | "
          f"client_mac={record['client_mac']}")

print()

all_ips  = sorted({r["src_ip"]  for r in artifacts} |
                  {r["dst_ip"]  for r in artifacts} |
                  {r["server_id"] for r in artifacts} -
                  {"N/A", "0.0.0.0", "255.255.255.255"})
all_macs = sorted({r["client_mac"] for r in artifacts} -
                  {"N/A", "ff:ff:ff:ff:ff:ff"})

print(f"  Уникальные IP-адреса:        {all_ips}")
print(f"  Уникальные MAC-адреса:       {all_macs}")

assigned = next((r["offered_ip"] for r in artifacts
                 if r["dhcp_type"] == "ACK" and r["offered_ip"] != "0.0.0.0"), "N/A")
lease    = next((r["lease_time_s"] for r in artifacts if r["dhcp_type"] == "ACK"), "N/A")
print(f"\n  Назначенный клиенту IP:  {assigned}")
print(f"  Время аренды (сек):      {lease}")

with open(OUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=artifacts[0].keys())
    writer.writeheader()
    writer.writerows(artifacts)
print(f"\n  Сохранено CSV  → {OUT_CSV.name}")

with open(OUT_JSON, "w") as f:
    json.dump(artifacts, f, indent=2, default=str)
print(f"  Сохранено JSON → {OUT_JSON.name}\n")

print("=" * 60)
print("Этап 3 — Визуализация результатов")
print("=" * 60)

sns.set_theme(style="whitegrid", palette="muted")

fig = plt.figure(figsize=(14, 10))
fig.suptitle("DHCP сетевой дамп — Форензика", fontsize=15, fontweight="bold")

ax1 = fig.add_subplot(2, 2, (1, 2))

type_colors = {
    "Discover": "#4C72B0",
    "Offer":    "#55A868",
    "Request":  "#C44E52",
    "ACK":      "#8172B2",
}

t0_dt = datetime.fromisoformat(str(artifacts[0]["timestamp"]))

def rel_ms(ts):
    dt = datetime.fromisoformat(str(ts))
    return (dt - t0_dt).total_seconds() * 1000

x_positions = [1, 3, 5, 7]
labels  = [r["dhcp_type"]         for r in artifacts]
colors  = [type_colors.get(l, "#999") for l in labels]
y_client = 1.0
y_server = 0.0

ax1.set_xlim(0, 8.5)
ax1.set_ylim(-0.5, 1.7)

for i, (x, label, color) in enumerate(zip(x_positions, labels, colors)):
    is_from_client = artifacts[i]["dhcp_type"] in ("Discover", "Request")
    y_start = y_client if is_from_client else y_server
    y_end   = y_server if is_from_client else y_client
    offset  = 0.08 if is_from_client else -0.08

    ax1.annotate(
        "",
        xy=(x, y_end), xytext=(x, y_start),
        arrowprops=dict(arrowstyle="-|>", color=color, lw=2.5,
                        mutation_scale=18),
    )
    y_mid = (y_start + y_end) / 2
    ax1.text(x + 0.15, y_mid + offset, label,
             color=color, fontsize=11, fontweight="bold", va="center")

    ts_str = f"+{rel_ms(artifacts[i]['timestamp']):.2f} ms"
    ax1.text(x, y_start + (-0.15 if is_from_client else 0.08),
             ts_str, ha="center", fontsize=8, color="#555")

ax1.axhline(y_client, color="#4C72B0", lw=1.5, ls="--", alpha=0.5)
ax1.axhline(y_server, color="#55A868", lw=1.5, ls="--", alpha=0.5)
ax1.text(0.05, y_client + 0.05, "Клиент  (MAC 00:0b:82:01:fc:42)",
         fontsize=9, color="#4C72B0", va="bottom")
ax1.text(0.05, y_server - 0.05, "Сервер  (192.168.0.1)",
         fontsize=9, color="#55A868", va="top")
ax1.set_xticks(x_positions)
ax1.set_xticklabels([f"Кадр {r['frame']}" for r in artifacts], fontsize=9)
ax1.set_title("Последовательность DORA  (Discover → Offer → Request → ACK)", fontsize=11)
ax1.set_yticks([])

ax2 = fig.add_subplot(2, 2, 3)

type_counts = {}
for r in artifacts:
    type_counts[r["dhcp_type"]] = type_counts.get(r["dhcp_type"], 0) + 1

bars = ax2.bar(
    list(type_counts.keys()),
    list(type_counts.values()),
    color=[type_colors.get(k, "#999") for k in type_counts],
    edgecolor="white",
    width=0.5,
)
for bar in bars:
    ax2.text(bar.get_x() + bar.get_width() / 2,
             bar.get_height() + 0.02,
             str(int(bar.get_height())),
             ha="center", va="bottom", fontweight="bold")

ax2.set_title("Пакеты по типу DHCP-сообщения", fontsize=11)
ax2.set_ylabel("Количество")
ax2.set_ylim(0, max(type_counts.values()) + 0.5)

ax3 = fig.add_subplot(2, 2, 4)
ax3.axis("off")

table_data = [
    ["Атрибут", "Значение"],
    ["MAC клиента",       artifacts[0]["client_mac"]],
    ["DHCP-сервер",       next((r["server_id"] for r in artifacts if r["server_id"] != "N/A"), "N/A")],
    ["Назначенный IP",    assigned],
    ["Маска подсети",     next((r["subnet_mask"] for r in artifacts if r["subnet_mask"] != "N/A"), "N/A")],
    ["Время аренды",      f"{int(lease) // 3600}ч {(int(lease) % 3600) // 60}м" if lease.isdigit() else lease],
    ["Время обновления",  next((f"{int(r['renewal_s'])//60}м" for r in artifacts if r["renewal_s"] != "N/A"), "N/A")],
    ["Время перепривязки",next((f"{int(r['rebind_s'])//60}м {int(r['rebind_s'])%60}с" for r in artifacts if r["rebind_s"] != "N/A"), "N/A")],
    ["Всего пакетов",     str(len(artifacts))],
    ["Дата захвата",      str(artifacts[0]["timestamp"])[:19]],
]

tbl = ax3.table(
    cellText=[row[1:] for row in table_data[1:]],
    rowLabels=[row[0] for row in table_data[1:]],
    colLabels=["Значение"],
    loc="center",
    cellLoc="left",
)
tbl.auto_set_font_size(False)
tbl.set_fontsize(9)
tbl.scale(1, 1.6)

for (row, col), cell in tbl.get_celld().items():
    if row == 0:
        cell.set_facecolor("#4C72B0")
        cell.set_text_props(color="white", fontweight="bold")
    elif row % 2 == 0:
        cell.set_facecolor("#f0f4f8")
    cell.set_edgecolor("#ccc")

ax3.set_title("Ключевые DHCP-артефакты", fontsize=11, pad=12)

plt.tight_layout()
plt.savefig(OUT_PLOT, dpi=150, bbox_inches="tight")
print(f"  Сохранён график → {OUT_PLOT.name}")
print("\nГотово.")
