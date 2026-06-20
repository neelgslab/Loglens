import os
import random
from datetime import datetime, timedelta


random.seed(42)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "sample.log")

NORMAL_IPS = [
    "103.48.198.141",
    "45.79.118.42",
    "8.8.8.8",
    "9.9.9.9",
    "66.249.66.1",
]

ATTACK_IPS = [
    "185.220.101.1",
    "51.15.76.10",
    "45.33.32.156",
]

NORMAL_PATHS = [
    "/",
    "/login",
    "/products",
    "/api/products",
    "/api/cart",
    "/checkout",
    "/contact",
    "/about",
    "/assets/app.js",
    "/assets/main.css",
    "/favicon.ico",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile/15E148 Safari/604.1",
]

ATTACK_USER_AGENTS = [
    "sqlmap/1.8.4#stable",
    "Mozilla/5.0 attack-scanner",
    "python-requests/2.31",
    "curl/8.4.0",
]


def make_log_line(ip_address, timestamp, method, path, status, bytes_sent, user_agent, referrer="-"):
    formatted_time = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0530")
    return (
        f'{ip_address} - - [{formatted_time}] '
        f'"{method} {path} HTTP/1.1" {status} {bytes_sent} '
        f'"{referrer}" "{user_agent}"'
    )


def normal_event(index, start_time):
    timestamp = start_time + timedelta(seconds=index * random.randint(5, 18))
    ip_address = random.choice(NORMAL_IPS)
    method = random.choice(["GET", "GET", "GET", "POST"])
    path = random.choice(NORMAL_PATHS)
    status = random.choice([200, 200, 200, 200, 301, 404])
    bytes_sent = random.randint(800, 28000)
    user_agent = random.choice(USER_AGENTS)

    return make_log_line(
        ip_address,
        timestamp,
        method,
        path,
        status,
        bytes_sent,
        user_agent,
    )


def attack_events(start_time):
    events = []

    sql_paths = [
        "/products?id=1%20OR%201=1--",
        "/search?q=test%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/api/products?category=1%27%20OR%20%271%27=%271",
        "/login?user=admin%27--",
        "/item?id=10%20AND%201=1",
        "/checkout?coupon=%27%20OR%20%271%27=%271",
    ]

    xss_paths = [
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E",
        "/profile?name=%3Csvg%20onload=alert(1)%3E",
        "/feedback?msg=javascript:alert(1)",
        "/review?body=%3Ciframe%20src=javascript:alert(1)%3E",
        "/support?message=%3Cbody%20onload=alert(1)%3E",
    ]

    traversal_paths = [
        "/../../etc/passwd",
        "/admin/../../../../etc/shadow",
        "/download?file=../../../../etc/passwd",
        "/static/..%2F..%2F..%2Fwindows%2Fwin.ini",
        "/backup?name=..%2F..%2F..%2Fetc%2Fhosts",
        "/files/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ]

    current_time = start_time + timedelta(minutes=15)

    for path in sql_paths:
        events.append(
            make_log_line(
                "51.15.76.10",
                current_time,
                "GET",
                path,
                random.choice([200, 400, 403, 500]),
                random.randint(1200, 9000),
                "sqlmap/1.8.4#stable",
            )
        )
        current_time += timedelta(seconds=random.randint(20, 55))

    current_time = start_time + timedelta(minutes=32)

    for path in xss_paths:
        events.append(
            make_log_line(
                "45.33.32.156",
                current_time,
                "GET",
                path,
                random.choice([200, 400, 403]),
                random.randint(900, 7000),
                random.choice(ATTACK_USER_AGENTS),
            )
        )
        current_time += timedelta(seconds=random.randint(18, 50))

    current_time = start_time + timedelta(minutes=46)

    for path in traversal_paths:
        events.append(
            make_log_line(
                "185.220.101.1",
                current_time,
                "GET",
                path,
                random.choice([200, 403, 404]),
                random.randint(500, 6000),
                random.choice(ATTACK_USER_AGENTS),
            )
        )
        current_time += timedelta(seconds=random.randint(22, 60))

    current_time = start_time + timedelta(minutes=62)

    for attempt in range(14):
        events.append(
            make_log_line(
                "185.220.101.1",
                current_time,
                "POST",
                "/login",
                401,
                random.randint(700, 2200),
                "Mozilla/5.0 brute-force-bot",
            )
        )
        current_time += timedelta(seconds=random.randint(3, 9))

    return events


def build_log_file():
    start_time = datetime(2026, 6, 19, 9, 0, 0)
    attacks = attack_events(start_time)
    normal_count = 600 - len(attacks)

    lines = []

    for index in range(normal_count):
        lines.append(normal_event(index, start_time))

    lines.extend(attacks)

    lines.sort(key=lambda line: line.split("[")[1].split("]")[0])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    print(f"Created sample.log with {len(lines)} lines")
    print("Demo IP locations included:")
    print("185.220.101.1 - Brandenburg an der Havel, Germany")
    print("51.15.76.10 - Haarlem, The Netherlands")
    print("45.33.32.156 - Fremont, United States")
    print("103.48.198.141 - New Delhi, India")
    print("45.79.118.42 - Sydney, Australia")


if __name__ == "__main__":
    build_log_file()
    