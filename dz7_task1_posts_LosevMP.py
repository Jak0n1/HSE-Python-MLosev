import requests

POSTS_URL = "https://dummyjson.com/posts"
POSTS_LIMIT = 5
TIMEOUT = 10


def get_posts(limit=POSTS_LIMIT): # Отправить GET-запрос к /posts и вернуть первые limit постов.
    response = requests.get(POSTS_URL, timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json() # DummyJSON возвращает объект, список постов лежит по ключу "posts".
    posts = data["posts"]
    return posts[:limit]


def print_posts(posts): # Выводим тело и заголовок
    for number, post in enumerate(posts, start=1):
        print(f"Пост {number}")
        print(f"Заголовок: {post['title']}")
        print(f"Текст: {post['body']}")
        print("-" * 40)


def main(): # тут собственно получим 5 постов
    print("Первые 5 постов из DummyJSON")
    print("=" * 40)

    try:
        posts = get_posts()
    except requests.RequestException as error:
        print(f"Не удалось получить посты: {error}")
        return

    print_posts(posts)


if __name__ == "__main__":
    main()
