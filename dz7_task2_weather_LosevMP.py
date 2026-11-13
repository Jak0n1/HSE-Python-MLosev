import os
import requests

WEATHER_URL = "https://api.openweathermap.org/data/2.5/weather"
TIMEOUT = 10


def get_weather(city, api_key): # Отправляем GET-запрос к OpenWeather и вернуть данные о погоде. Возвращает словарь с ответом API или None, если город не найден.
    params = { 
        "q": city,
        "appid": api_key,
        "units": "metric",
        "lang": "ru",
    }
    response = requests.get(WEATHER_URL, params=params, timeout=TIMEOUT)

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return response.json()


def print_weather(weather): # Выводим текущую температуру и описание погоды
    city = weather["name"]
    temperature = weather["main"]["temp"]
    description = weather["weather"][0]["description"]

    print(f"Город: {city}")
    print(f"Температура: {temperature} °C")
    print(f"Описание: {description}")


def main(): # Запросить город у пользователя и вывести погоду в нём
    api_key = os.getenv("OPENWEATHER_API_KEY")
    if not api_key:
        api_key = input("Введите API-ключ OpenWeather: ").strip()

    city = input("Введите название города: ").strip()
    if not city:
        print("Название города не может быть пустым.")
        return

    try:
        weather = get_weather(city, api_key)
    except requests.HTTPError as error:
        if error.response.status_code == 401:
            print("Неверный API-ключ OpenWeather.")
        else:
            print(f"Ошибка API: {error}")
        return
    except requests.RequestException as error:
        print(f"Не удалось получить погоду: {error}")
        return

    if weather is None:
        print(f"Город «{city}» не найден.")
        return

    print_weather(weather)


if __name__ == "__main__":
    main()
