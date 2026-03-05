import hashlib
import json
import os
import sys

import requests

API_KEY = os.environ.get("VT_API_KEY", "")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}


def get_file_report(file_hash: str) -> dict:
    url = f"{BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()


def scan_file(file_path: str) -> dict:
    url = f"{BASE_URL}/files"
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(url, headers=HEADERS, files=files)
    response.raise_for_status()
    return response.json()


def scan_url(target_url: str) -> dict:
    url = f"{BASE_URL}/urls"
    response = requests.post(url, headers=HEADERS, data={"url": target_url})
    response.raise_for_status()
    return response.json()


def print_file_report(report: dict) -> None:
    attrs = report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    print("=" * 60)
    print("Отчёт VirusTotal")
    print("=" * 60)
    print(f"  Имя файла:        {attrs.get('meaningful_name', 'N/A')}")
    print(f"  SHA-256:           {attrs.get('sha256', 'N/A')}")
    print(f"  Размер:            {attrs.get('size', 'N/A')} байт")
    print(f"  Тип:               {attrs.get('type_description', 'N/A')}")
    print()
    print("Результаты сканирования:")
    print(f"  Вредоносный:       {stats.get('malicious', 0)}")
    print(f"  Подозрительный:    {stats.get('suspicious', 0)}")
    print(f"  Безопасный:        {stats.get('undetected', 0)}")
    print(f"  Не обработано:     {stats.get('type-unsupported', 0)}")
    print(f"  Ошибка:            {stats.get('failure', 0)}")
    print("=" * 60)

    # Полный JSON-ответ
    print("\nПолный JSON-ответ:")
    print(json.dumps(report, indent=2, ensure_ascii=False))


def main():
    if not API_KEY:
        print("Ошибка: не задана переменная окружения VT_API_KEY.")
        print("Установите её командой: export VT_API_KEY=\"ваш_ключ\"")
        sys.exit(1)

    if len(sys.argv) > 1:
        # Если передан аргумент — считаем его SHA-256 хешем файла
        file_hash = sys.argv[1]
        print(f"Запрос отчёта для хеша: {file_hash}")
    else:
        # Хеш тестового файла EICAR (стандартный антивирусный тест-файл)
        # https://en.wikipedia.org/wiki/EICAR_test_file
        eicar_content = (
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
            b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        file_hash = hashlib.sha256(eicar_content).hexdigest()
        print(f"Используется тестовый EICAR-файл (SHA-256: {file_hash})")

    try:
        report = get_file_report(file_hash)
        print_file_report(report)
    except requests.exceptions.HTTPError as e:
        print(f"HTTP ошибка: {e}")
        print(f"Ответ сервера: {e.response.text}")
    except requests.exceptions.ConnectionError:
        print("Ошибка подключения к VirusTotal API.")


if __name__ == "__main__":
    main()
