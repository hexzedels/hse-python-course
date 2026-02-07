"""
Анализ и визуализация событий информационной безопасности.
Загрузка данных из events.json, анализ распределения по типам (signature)
и построение графика с помощью Pandas, Matplotlib и Seaborn.
"""

import json
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_events(filepath: str) -> pd.DataFrame:
    """Загружает события из JSON-файла в DataFrame."""
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    return pd.DataFrame(data["events"])


def analyze_signatures(df: pd.DataFrame) -> pd.Series:
    """Подсчитывает количество событий каждого типа."""
    counts = df["signature"].value_counts()
    print("Распределение событий по типам (signature):\n")
    print(counts.to_string())
    print(f"\nВсего событий: {len(df)}")
    print(f"Уникальных типов: {df['signature'].nunique()}")
    return counts


def plot_signature_distribution(counts: pd.Series) -> None:
    """Строит столбчатый график распределения типов событий."""
    plt.figure(figsize=(12, 6))
    sns.barplot(x=counts.values, y=counts.index, hue=counts.index, palette="viridis", legend=False)
    plt.xlabel("Количество событий")
    plt.ylabel("Тип события (signature)")
    plt.title("Распределение событий ИБ по типам")
    plt.tight_layout()
    plt.savefig(Path(__file__).parent / "events_distribution.png", dpi=150)
    plt.show()


if __name__ == "__main__":
    events_path = Path(__file__).parent / "events.json"
    df = load_events(events_path)
    counts = analyze_signatures(df)
    plot_signature_distribution(counts)
