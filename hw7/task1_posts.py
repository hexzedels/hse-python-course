"""
Задание 1. Получение данных из публичного API
Скрипт отправляет GET-запрос к JSONPlaceholder /posts
и выводит заголовки и тела первых 5 постов.
"""

import requests


def get_first_posts(count: int = 5) -> None:
    """Получает и выводит первые N постов из JSONPlaceholder API."""
    url = "https://jsonplaceholder.typicode.com/posts"

    response = requests.get(url)
    response.raise_for_status()

    posts = response.json()

    print(f"Первые {count} постов из JSONPlaceholder:\n")
    print("=" * 60)

    for i, post in enumerate(posts[:count], 1):
        print(f"\nПост #{i}")
        print(f"Заголовок: {post['title']}")
        print(f"Тело: {post['body']}")
        print("-" * 60)


if __name__ == "__main__":
    get_first_posts(5)
