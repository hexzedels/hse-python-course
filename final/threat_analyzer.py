"""Инструмент анализа угроз безопасности.

Собирает данные из Suricata-логов и Vulners API, анализирует угрозы,
симулирует ответные меры и формирует отчёт с визуализацией.
"""

import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import requests
import seaborn as sns

DIR = Path(__file__).parent

# ── Встроенные данные (фоллбэк, если Vulners API недоступен) ─────────────

SAMPLE_VULNS: list[dict] = [
    {"id": "CVE-2024-6387", "title": "OpenSSH regreSSHion RCE", "cvss": 9.8, "software": "openssh"},
    {"id": "CVE-2024-3094", "title": "XZ Utils Backdoor", "cvss": 10.0, "software": "xz"},
    {"id": "CVE-2023-44487", "title": "HTTP/2 Rapid Reset DDoS", "cvss": 7.5, "software": "nginx"},
    {"id": "CVE-2023-38408", "title": "OpenSSH Agent RCE", "cvss": 9.8, "software": "openssh"},
    {"id": "CVE-2023-4863", "title": "libwebp Heap Buffer Overflow", "cvss": 8.8, "software": "libwebp"},
    {"id": "CVE-2024-21626", "title": "runc Container Escape", "cvss": 8.6, "software": "docker"},
    {"id": "CVE-2023-23397", "title": "Outlook NTLM Relay", "cvss": 9.1, "software": "outlook"},
    {"id": "CVE-2024-1709", "title": "ConnectWise ScreenConnect Auth Bypass", "cvss": 10.0, "software": "connectwise"},
    {"id": "CVE-2023-20198", "title": "Cisco IOS XE Web UI Privilege Escalation", "cvss": 10.0, "software": "cisco"},
    {"id": "CVE-2023-27997", "title": "FortiOS Heap Overflow", "cvss": 9.8, "software": "fortinet"},
    {"id": "CVE-2024-0012", "title": "PAN-OS Auth Bypass", "cvss": 9.8, "software": "paloalto"},
    {"id": "CVE-2023-36884", "title": "Office HTML RCE", "cvss": 7.5, "software": "office"},
]

SOFT_TO_CHECK: list[str] = ["openssh", "nginx", "docker", "xz"]


# ── Загрузка логов Suricata ──────────────────────────────────────────────

def load_suricata_logs(path: Path) -> pd.DataFrame:
    """Загружает JSON-логи Suricata и возвращает DataFrame."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    rows = []
    for entry in data:
        rows.append({
            "timestamp": entry["timestamp"],
            "src_ip": entry["src_ip"],
            "dest_ip": entry["dest_ip"],
            "signature": entry["alert"]["signature"],
            "severity": entry["alert"]["severity"],
            "proto": entry["proto"],
            "dest_port": entry["dest_port"],
        })
    return pd.DataFrame(rows)


# ── Запрос к Vulners API ─────────────────────────────────────────────────

def fetch_vulners(software_list: list[str]) -> list[dict]:
    """Запрашивает уязвимости через Vulners API; при ошибке — фоллбэк."""
    api_key = os.environ.get("VULNERS_API_KEY")
    if not api_key:
        print("[!] VULNERS_API_KEY не задан — используются встроенные данные")
        return SAMPLE_VULNS

    results: list[dict] = []
    for soft in software_list:
        try:
            resp = requests.get(
                "https://vulners.com/api/v3/burp/software/",
                params={"software": soft, "version": "any", "type": "cpe", "apiKey": api_key},
                timeout=10,
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("result") != "OK":
                continue
            for item in body.get("data", {}).get("search", []):
                src = item.get("_source", {})
                results.append({
                    "id": src.get("id", "N/A"),
                    "title": src.get("title", "N/A"),
                    "cvss": src.get("cvss", {}).get("score", 0.0),
                    "software": soft,
                })
        except Exception as exc:
            print(f"[!] Ошибка Vulners для {soft}: {exc}")
    if not results:
        print("[!] API не вернул данных — используются встроенные данные")
        return SAMPLE_VULNS
    return results


# ── Анализ ────────────────────────────────────────────────────────────────

def analyze_suricata(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Считает алерты по IP и выделяет подозрительные (>= 3 алертов)."""
    ip_counts = (
        df.groupby("src_ip")
        .size()
        .reset_index(name="alert_count")
        .sort_values("alert_count", ascending=False)
    )
    suspicious = ip_counts[ip_counts["alert_count"] >= 3].copy()
    return ip_counts, suspicious


def filter_high_vulns(vulns: list[dict], min_cvss: float = 7.0) -> pd.DataFrame:
    """Фильтрует уязвимости по CVSS >= min_cvss."""
    df = pd.DataFrame(vulns)
    return df[df["cvss"] >= min_cvss].sort_values("cvss", ascending=False).reset_index(drop=True)


# ── Реагирование (симуляция) ──────────────────────────────────────────────

def respond_to_threats(suspicious_ips: pd.DataFrame, vulns_df: pd.DataFrame) -> list[dict]:
    """Симулирует блокировку IP и оповещения по критическим CVE."""
    actions: list[dict] = []

    print("=" * 60)
    print("РЕАГИРОВАНИЕ НА УГРОЗЫ")
    print("=" * 60)

    for _, row in suspicious_ips.iterrows():
        ip = row["src_ip"]
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        print(f"[BLOCK] Блокировка IP {ip} ({row['alert_count']} алертов): {cmd}")
        actions.append({"type": "block_ip", "ip": ip, "command": cmd})

    critical = vulns_df[vulns_df["cvss"] >= 9.0]
    for _, row in critical.iterrows():
        msg = f"КРИТИЧЕСКАЯ УЯЗВИМОСТЬ {row['id']} (CVSS {row['cvss']}): {row['title']}"
        print(f"[TELEGRAM] Отправка уведомления: {msg}")
        actions.append({"type": "telegram_alert", "cve": row["id"], "message": msg})

    print(f"\nВсего действий: {len(actions)}")
    return actions


# ── Визуализация ──────────────────────────────────────────────────────────

def build_charts(ip_counts: pd.DataFrame, vulns_df: pd.DataFrame, out: Path) -> None:
    """Строит графики: топ-5 IP и распределение CVSS."""
    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    top5 = ip_counts.head(5)
    sns.barplot(data=top5, x="src_ip", y="alert_count", hue="src_ip", ax=axes[0], palette="Reds_r", legend=False)
    axes[0].set_title("Топ-5 IP по количеству алертов")
    axes[0].set_xlabel("IP-адрес")
    axes[0].set_ylabel("Кол-во алертов")
    axes[0].tick_params(axis="x", rotation=25)

    if not vulns_df.empty:
        sns.barplot(data=vulns_df, x="id", y="cvss", hue="id", ax=axes[1], palette="YlOrRd", legend=False)
        axes[1].set_title("CVSS-оценки найденных уязвимостей")
        axes[1].set_xlabel("CVE")
        axes[1].set_ylabel("CVSS")
        axes[1].tick_params(axis="x", rotation=35)
    else:
        axes[1].text(0.5, 0.5, "Нет данных", ha="center", va="center", fontsize=14)
        axes[1].set_title("CVSS-оценки найденных уязвимостей")

    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"[OK] График сохранён: {out}")


# ── Сохранение отчёта ─────────────────────────────────────────────────────

def save_report(
    suspicious: pd.DataFrame,
    vulns_df: pd.DataFrame,
    actions: list[dict],
) -> None:
    """Сохраняет отчёт в JSON и CSV."""
    report = {
        "suspicious_ips": suspicious.to_dict(orient="records"),
        "high_vulns": vulns_df.to_dict(orient="records"),
        "actions": actions,
    }
    json_path = DIR / "report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[OK] JSON-отчёт: {json_path}")

    rows: list[dict] = []
    for _, r in suspicious.iterrows():
        rows.append({"тип": "Подозрительный IP", "идентификатор": r["src_ip"],
                      "значение": r["alert_count"], "описание": "алертов"})
    for _, r in vulns_df.iterrows():
        rows.append({"тип": "Уязвимость", "идентификатор": r["id"],
                      "значение": r["cvss"], "описание": r["title"]})

    csv_path = DIR / "report.csv"
    pd.DataFrame(rows).to_csv(csv_path, index=False, encoding="utf-8-sig")
    print(f"[OK] CSV-отчёт: {csv_path}")


# ── Главная функция ───────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("АНАЛИЗ УГРОЗ БЕЗОПАСНОСТИ")
    print("=" * 60)

    # 1. Загрузка логов Suricata
    log_path = DIR / "sample_suricata.json"
    df = load_suricata_logs(log_path)
    print(f"\n[1] Загружено {len(df)} записей из Suricata-логов")

    # 2. Анализ алертов
    ip_counts, suspicious = analyze_suricata(df)
    print(f"[2] Уникальных IP: {len(ip_counts)}, подозрительных (>=3 алертов): {len(suspicious)}")
    print(suspicious.to_string(index=False))

    # 3. Запрос уязвимостей
    print(f"\n[3] Запрос уязвимостей для: {', '.join(SOFT_TO_CHECK)}")
    vulns = fetch_vulners(SOFT_TO_CHECK)
    vulns_df = filter_high_vulns(vulns)
    print(f"    Найдено уязвимостей с CVSS >= 7.0: {len(vulns_df)}")
    if not vulns_df.empty:
        print(vulns_df[["id", "title", "cvss"]].to_string(index=False))

    # 4. Реагирование
    print()
    actions = respond_to_threats(suspicious, vulns_df)

    # 5. Визуализация
    print("\n" + "=" * 60)
    print("ФОРМИРОВАНИЕ ОТЧЁТА")
    print("=" * 60)
    build_charts(ip_counts, vulns_df, DIR / "threats_chart.png")

    # 6. Сохранение отчёта
    save_report(suspicious, vulns_df, actions)

    print("\n" + "=" * 60)
    print("АНАЛИЗ ЗАВЕРШЁН")
    print("=" * 60)


if __name__ == "__main__":
    main()
