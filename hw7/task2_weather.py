"""
Задание 2. Работа с параметрами запроса
Программа принимает название города от пользователя,
отправляет GET-запрос к OpenWeather API и выводит
текущую температуру и описание погоды.
"""

import os

import requests
from dotenv import load_dotenv

load_dotenv()


def get_weather(city: str, api_key: str) -> None:
    """Получает и выводит погоду для указанного города."""
    url = "https://api.openweathermap.org/data/2.5/weather"

    params = {
        "q": city,
        "appid": api_key,
        "units": "metric",  # Температура в Цельсиях
        "lang": "ru"        # Описание на русском
    }

    response = requests.get(url, params=params)

    if response.status_code == 401:
        print("Ошибка: неверный API-ключ")
        return
    elif response.status_code == 404:
        print(f"Ошибка: город '{city}' не найден")
        return

    response.raise_for_status()
    data = response.json()

    temperature = data["main"]["temp"]
    description = data["weather"][0]["description"]

    print(f"\nПогода в городе {city}:")
    print(f"Температура: {temperature}°C")
    print(f"Описание: {description}")


def main():
    api_key = os.getenv("OPENWEATHER_API_KEY")

    if not api_key:
        print("Ошибка: API-ключ не найден.")
        print("Создайте файл .env с содержимым: OPENWEATHER_API_KEY=ваш_ключ")
        return

    city = input("Введите название города: ").strip()

    if not city:
        print("Ошибка: название города не может быть пустым")
        return

    get_weather(city, api_key)


if __name__ == "__main__":
    main()
