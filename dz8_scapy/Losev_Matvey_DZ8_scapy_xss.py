#
# Режимы:
#   sniff   -- перехватить трафик и сохранить в .pcap;
#   send    -- отправить XSS-нагрузки, параллельно записывая трафик;
#   analyze -- разобрать .pcap: запросы, ответы (включая gzip),
#              поиск XSS-полезных нагрузок.
#
# Примеры (перехват живого трафика требует прав root):
#   sudo python Losev_Matvey_DZ8_scapy_xss.py sniff -f 'tcp port 8008'
#   sudo python Losev_Matvey_DZ8_scapy_xss.py send \
#       -u http://localhost:8008/search --param q \
#       --payload '<script>alert(1)</script>'
#   python Losev_Matvey_DZ8_scapy_xss.py analyze -p traffic.pcap \
#       --payload '<script>alert(1)</script>'

import argparse
import gzip
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

from scapy.all import IP, TCP, rdpcap, sniff, wrpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

DEFAULT_FILTER = "tcp port 80 or tcp port 8008"  # Gruyere слушает 8008
USER_AGENT = "Mozilla/5.0 (DZ8 Scapy lab)"
BODY_LIMIT = 1500  # сколько символов тела печатать
INDENT = "    "
# Служебные поля Scapy (не заголовки): не попадают в словарь заголовков.
META_FIELDS = {"Method", "Path", "Http_Version", "Status_Code",
               "Reason_Phrase"}


def decode(value):  # байтовое поле Scapy -> обычная строка
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return "" if value is None else str(value)


def headers_dict(message):  # словарь заголовков HTTP-сообщения
    return {key.replace("_", "-"): decode(value)
            for key, value in message.fields.items()
            if key not in META_FIELDS}


def message_body(message):  # тело сообщения: байты после заголовков
    return bytes(message.payload)


def stream_key(packet):  # ключ направления TCP-потока
    return (packet[IP].src, packet[TCP].sport,
            packet[IP].dst, packet[TCP].dport)


def http_streams(packets):  # собрать TCP-потоки из отдельных пакетов
    streams = {}
    seen = set()
    for packet in packets:
        if TCP not in packet:
            continue
        payload = bytes(packet[TCP].payload)
        if not payload:
            continue
        key = stream_key(packet)
        marker = (key, packet[TCP].seq, payload)
        if marker in seen:  # дубликат сегмента или ретрансляция TCP
            continue
        seen.add(marker)
        streams[key] = streams.get(key, b"") + payload
    return streams


def content_length(head):  # значение Content-Length из блока заголовков
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            return int(value.strip())
    return None


def split_messages(data):  # нарезать поток байтов на HTTP-сообщения
    messages = []
    offset = 0
    while offset < len(data):
        head_end = data.find(b"\r\n\r\n", offset)
        if head_end == -1:
            break
        head = data[offset:head_end]
        body_start = head_end + 4
        length = content_length(head)
        if head.startswith(b"HTTP") and length is None:
            body_end = len(data)  # ответ до закрытия соединения
        elif length is None:
            body_end = body_start  # у запроса без Content-Length тела нет
        else:
            body_end = min(body_start + length, len(data))
        messages.append((head, data[body_start:body_end]))
        offset = body_end
    return messages


def parse_message(head, body):  # разобрать сообщение слоем HTTP из Scapy
    try:
        layer = HTTP(head + b"\r\n\r\n" + body)
    except Exception:  # не HTTP-сообщение -- пропускаем
        return None
    for message_class in (HTTPRequest, HTTPResponse):
        if message_class in layer:
            return layer[message_class]
    return None


def extract_pairs(packets):  # пары «запрос -- ответ» по TCP-соединениям
    connections = {}
    for key, data in http_streams(packets).items():
        # Оба направления одного соединения сводим к общему ключу.
        connection_key = min(key, (key[2], key[3], key[0], key[1]))
        bucket = connections.setdefault(
            connection_key, {"requests": [], "responses": []})
        for head, body in split_messages(data):
            message = parse_message(head, body)
            if message is None:
                continue
            kind = "requests" if isinstance(message, HTTPRequest) \
                else "responses"
            bucket[kind].append(message)
    return [pair for bucket in connections.values()
            for pair in zip(bucket["requests"], bucket["responses"])]


def decode_body(message_headers, body):  # распаковать gzip и декодировать
    # Доработка из задания: ответ может быть сжат, тело сначала
    # распаковывается по Content-Encoding, потом декодируется по
    # кодировке из Content-Type.
    if not body:
        return ""
    encoding = message_headers.get("Content-Encoding", "").lower()
    try:
        if "gzip" in encoding:
            body = gzip.decompress(body)
        elif "deflate" in encoding:
            try:
                body = zlib.decompress(body)
            except zlib.error:
                body = zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        pass
    charset = "utf-8"
    content_type = message_headers.get("Content-Type", "")
    if "charset=" in content_type:
        charset = content_type.split("charset=")[-1].split(";")[0].strip()
    return body.decode(charset, errors="replace")


def request_url(request):  # полный URL из заголовка Host и пути
    host = decode(request.fields.get("Host"))
    return f"http://{host}{decode(request.Path)}"


def indent_block(text):  # сдвинуть каждую строку на один отступ вправо
    return "\n".join(f"{INDENT}{line}" for line in text.splitlines())


def print_pair(index, request, response):  # разбор одной пары на экран
    print(f"--- Пара {index}: {decode(request.Method)} "
          f"{request_url(request)}")
    print(f"{INDENT}Заголовки запроса:")
    request_headers = headers_dict(request)
    for name, value in request_headers.items():
        print(f"{INDENT}  {name}: {value}")
    body = decode_body(request_headers, message_body(request))
    if body:
        print(f"{INDENT}Тело запроса:")
        print(indent_block(body[:BODY_LIMIT]))

    status = decode(response.fields.get("Status_Code"))
    print(f"{INDENT}<-- ответ: HTTP {status}")
    print(f"{INDENT}Заголовки ответа:")
    response_headers = headers_dict(response)
    for name, value in response_headers.items():
        print(f"{INDENT}  {name}: {value}")
    body = decode_body(response_headers, message_body(response))
    if body:
        print(f"{INDENT}Тело ответа (первые {BODY_LIMIT} символов):")
        print(indent_block(body[:BODY_LIMIT]))


def find_payload(pairs, payload):  # где нагрузка в запросе и в ответе
    found = 0
    for index, (request, response) in enumerate(pairs, 1):
        method = decode(request.Method)
        path = decode(request.Path)
        request_headers = headers_dict(request)
        body = decode_body(request_headers, message_body(request))
        places = []
        if payload in urllib.parse.unquote(path):
            places.append("в URL (GET-параметр)")
        if payload in body:
            places.append("в теле POST-запроса")
        response_headers = headers_dict(response)
        response_body = decode_body(response_headers,
                                    message_body(response))
        if not places:  # в запросе нет -- ищем в ответе (хранимый XSS)
            if payload in response_body:
                found += 1
                print(f"--- Пара {index}: {method} {path}")
                print(f"{INDENT}В запросе: нагрузки нет")
                print(f"{INDENT}В ответе: отражена (следы хранимого XSS)")
            continue
        found += 1
        print(f"--- Пара {index}: {method} {path}")
        print(f"{INDENT}В запросе: {' и '.join(places)} "
              f"(метод {method})")
        position = response_body.find(payload)
        if position == -1:
            place = "не отражается (следов полезной нагрузки нет)"
        else:
            before = response_body[:position].lower()
            if "<script" in before:  # до нагрузки уже открыт <script>
                place = "внутри тега <script> (JavaScript)"
            elif before.rstrip().endswith(("=", '"', "'")):
                place = "в атрибуте HTML-тега"
            else:
                place = "в HTML-теле страницы"
            start = max(0, position - 60)
            context = response_body[start:position + len(payload) + 60]
            place = f"{place}; фрагмент: ...{context}..."
        print(f"{INDENT}В ответе: {place}")
    print(f"Итого пар с полезной нагрузкой: {found}")


def send_payload(url, param, payload, method):  # отправить одну нагрузку
    if method == "GET":
        url = f"{url}?{urllib.parse.urlencode({param: payload})}"
        data = None
    else:  # POST: нагрузка уходит в теле запроса
        data = urllib.parse.urlencode({param: payload}).encode()
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"User-Agent": USER_AGENT})
    print(f"--> {method} {url}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
            print(f"{INDENT}<-- статус {response.status}")
    except urllib.error.HTTPError as error:
        print(f"{INDENT}<-- ошибка сервера: HTTP {error.code}")


def run_sniff(args):  # этап 2: перехват трафика и сохранение в .pcap
    print(f"Перехват трафика по фильтру «{args.filter}»...")
    packets = sniff(iface=args.interface, filter=args.filter,
                    timeout=args.timeout or None,
                    count=args.count)
    wrpcap(args.output, packets)
    print(f"Сохранено пакетов: {len(packets)} -> {args.output}")
    pairs = extract_pairs(packets)
    if not pairs:
        print("HTTP-сообщения не найдены.")
        return
    print(f"HTTP-пар найдено: {len(pairs)}")
    for index, (request, response) in enumerate(pairs, 1):
        print_pair(index, request, response)
        print()


def run_send(args):  # этап 3: XSS-нагрузки с записью трафика
    payloads = list(args.payload)
    if args.payload_file:  # нагрузки из файла, по одной в строке
        with open(args.payload_file, encoding="utf-8") as file:
            payloads += [line.strip() for line in file if line.strip()]
    if not payloads:
        raise SystemExit("Не задано ни одной полезной нагрузки.")
    captured = {}

    def capture():  # перехват идёт в фоне, пока отправляем нагрузки
        captured["packets"] = sniff(iface=args.interface,
                                    filter=args.filter,
                                    timeout=args.capture_time)

    print("Запускаю перехват трафика в фоновом режиме...")
    thread = threading.Thread(target=capture)
    thread.start()
    time.sleep(1)  # даём sniff открыть сокет
    for payload in payloads:
        send_payload(args.url, args.param, payload, args.method)
    thread.join()
    packets = captured.get("packets", [])
    wrpcap(args.output, packets)
    print(f"Сохранено пакетов: {len(packets)} -> {args.output}")


def run_analyze(args):  # этап 4: разбор сохранённого .pcap-файла
    packets = rdpcap(args.pcap)
    pairs = extract_pairs(packets)
    print(f"Пакетов в файле: {len(packets)}")
    print(f"HTTP-пар «запрос -- ответ»: {len(pairs)}")
    for index, (request, response) in enumerate(pairs[:args.limit], 1):
        print_pair(index, request, response)
        print()
    if args.payload:  # ищем следы XSS-атаки
        find_payload(pairs, args.payload)


def build_parser():  # аргументы командной строки
    parser = argparse.ArgumentParser(
        description="ДЗ8: перехват и анализ HTTP-трафика (Scapy + XSS)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sniff_parser = subparsers.add_parser(
        "sniff", help="перехватить трафик и сохранить в .pcap")
    sniff_parser.add_argument("-i", "--interface",
                              help="сетевой интерфейс")
    sniff_parser.add_argument("-f", "--filter", default=DEFAULT_FILTER,
                              help="BPF-фильтр")
    sniff_parser.add_argument("-o", "--output",
                              default="gruyere_traffic.pcap",
                              help="файл .pcap")
    sniff_parser.add_argument("-t", "--timeout", type=int, default=60,
                              help="длительность перехвата, секунд")
    sniff_parser.add_argument("-c", "--count", type=int, default=0,
                              help="остановиться после N пакетов")

    send_parser = subparsers.add_parser(
        "send", help="отправить XSS-нагрузки с записью трафика")
    send_parser.add_argument("-u", "--url", required=True,
                             help="адрес, напр. http://localhost:8008/search")
    send_parser.add_argument("--param", default="q",
                             help="имя параметра с нагрузкой")
    send_parser.add_argument("--payload", action="append", default=[],
                             help="полезная нагрузка (можно повторять)")
    send_parser.add_argument("--payload-file",
                             help="файл с нагрузками, по одной в строке")
    send_parser.add_argument("--method", choices=["GET", "POST"],
                             default="GET")
    send_parser.add_argument("-o", "--output",
                             default="gruyere_traffic.pcap",
                             help="файл .pcap")
    send_parser.add_argument("-t", "--capture-time", type=int, default=20,
                             help="сколько секунд слушать после отправки")
    send_parser.add_argument("-i", "--interface",
                             help="сетевой интерфейс")
    send_parser.add_argument("-f", "--filter", default=DEFAULT_FILTER,
                             help="BPF-фильтр")

    analyze_parser = subparsers.add_parser(
        "analyze", help="разобрать сохранённый .pcap")
    analyze_parser.add_argument("-p", "--pcap", required=True,
                                help="файл .pcap")
    analyze_parser.add_argument("--payload",
                                help="искать эту полезную нагрузку")
    analyze_parser.add_argument("--limit", type=int, default=10,
                                help="сколько HTTP-пар печатать")
    return parser


def main():  # точка входа: разбор аргументов и запуск режима
    args = build_parser().parse_args()
    if args.command == "sniff":
        run_sniff(args)
    elif args.command == "send":
        run_send(args)
    elif args.command == "analyze":
        run_analyze(args)


if __name__ == "__main__":
    main()
