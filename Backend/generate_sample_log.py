import random
from datetime import datetime, timedelta
from pathlib import Path


OUTPUT_FILE = Path(__file__).with_name("sample.log")
TOTAL_LINES = 600

random.seed(42)

normal_ips = [
    "8.8.8.8",
    "9.9.9.9",
    "45.79.118.42",
    "103.48.198.141",
    "208.67.222.222",
    "66.249.66.1"
]

attack_ips = {
    "sqli": "45.33.32.156",
    "xss": "51.15.76.10",
    "traversal": "185.220.101.1",
    "bruteforce": "185.220.101.1"
}

normal_paths = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/products.php?id=12",
    "/products.php?id=18",
    "/blog/nginx-basic-hardening",
    "/assets/logo.png",
    "/assets/main.css",
    "/assets/app.js",
    "/api/products",
    "/api/cart",
    "/login",
    "/admin/login.php",
    "/wp-admin/"
]

sqli_paths = [
    "/products.php?id=12%27%20OR%201%3D1--",
    "/search.php?q=-1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/news.php?id=3%20AND%201%3D1",
    "/item.php?id=5%27%20OR%20%271%27%3D%271",
    "/product.php?id=9%3BSELECT%20sleep(5)"
]

xss_paths = [
    "/comment.php?msg=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
    "/profile.php?next=javascript:alert(1)",
    "/contact.php?name=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E",
    "/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E"
]

traversal_paths = [
    "/download.php?file=../../../../etc/passwd",
    "/cgi-bin/%2e%2e/%2e%2e/%2e%2e/bin/sh",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/view?template=../../../../windows/win.ini"
]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile/15E148 Safari/604.1",
    "curl/8.1.2",
    "sqlmap/1.8.4#stable (https://sqlmap.org)"
]

referrers = [
    "-",
    "https://example.com/",
    "https://example.com/products",
    "https://example.com/login",
    "https://google.com/"
]


def apache_time(timestamp):
    return timestamp.strftime("%d/%b/%Y:%H:%M:%S +0530")


def make_line(ip, timestamp, method, path, status, size, referrer, user_agent):
    return (
        f'{ip} - - [{apache_time(timestamp)}] '
        f'"{method} {path} HTTP/1.1" {status} {size} '
        f'"{referrer}" "{user_agent}"\n'
    )


def make_normal_line(timestamp):
    return make_line(
        ip=random.choice(normal_ips),
        timestamp=timestamp,
        method=random.choice(["GET", "GET", "GET", "POST"]),
        path=random.choice(normal_paths),
        status=random.choice([200, 200, 200, 301, 302, 404]),
        size=random.randint(250, 25000),
        referrer=random.choice(referrers),
        user_agent=random.choice(user_agents[:4])
    )


def make_sqli_line(timestamp):
    return make_line(
        ip=attack_ips["sqli"],
        timestamp=timestamp,
        method="GET",
        path=random.choice(sqli_paths),
        status=random.choice([400, 403, 500]),
        size=random.randint(280, 900),
        referrer="-",
        user_agent=random.choice([
            user_agents[5],
            user_agents[2],
            user_agents[4]
        ])
    )


def make_xss_line(timestamp):
    return make_line(
        ip=attack_ips["xss"],
        timestamp=timestamp,
        method="GET",
        path=random.choice(xss_paths),
        status=random.choice([200, 302, 403]),
        size=random.randint(300, 1200),
        referrer="-",
        user_agent=random.choice(user_agents[:4])
    )


def make_traversal_line(timestamp):
    return make_line(
        ip=attack_ips["traversal"],
        timestamp=timestamp,
        method="GET",
        path=random.choice(traversal_paths),
        status=random.choice([400, 403, 404]),
        size=random.randint(220, 700),
        referrer="-",
        user_agent=random.choice([
            user_agents[2],
            user_agents[4]
        ])
    )


def make_brute_force_line(timestamp):
    return make_line(
        ip=attack_ips["bruteforce"],
        timestamp=timestamp,
        method="POST",
        path="/login",
        status=401,
        size=random.randint(160, 240),
        referrer="https://example.com/login",
        user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0"
    )


def make_sample_log():
    current_time = datetime(2026, 6, 19, 9, 0, 0)
    lines = []

    first_brute_force_block = set(range(280, 287))
    second_brute_force_block = set(range(440, 447))

    for line_number in range(1, TOTAL_LINES + 1):
        current_time += timedelta(seconds=random.randint(3, 25))

        if line_number in first_brute_force_block:
            line = make_brute_force_line(current_time)
        elif line_number in second_brute_force_block:
            line = make_brute_force_line(current_time)
        elif line_number % 67 == 0:
            line = make_sqli_line(current_time)
        elif line_number % 83 == 0:
            line = make_xss_line(current_time)
        elif line_number % 109 == 0:
            line = make_traversal_line(current_time)
        else:
            line = make_normal_line(current_time)

        lines.append(line)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.writelines(lines)

    print("Created sample.log")
    print("Path:", OUTPUT_FILE)
    print("Lines:", len(lines))


if __name__ == "__main__":
    make_sample_log()
    