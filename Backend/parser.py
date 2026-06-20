import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from detector import detect_attack
from geo_lookup import get_geo_info, get_geoip_status


LOG_PATTERN = r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>.*?)\]\s+"(?P<method>\S+)\s+(?P<path>.*?)\s+HTTP/(?P<http_version>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)")?'

BRUTE_FORCE_THRESHOLD = 7
EVENT_LIMIT = 1000
PROGRESS_STEP = 50 * 1024 * 1024
CANCEL_CHECK_LINES = 5000


class AnalysisCancelled(Exception):
    pass


def get_hour(timestamp):
    try:
        parsed_time = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
        return parsed_time.strftime("%d %b %Y %H:00")
    except ValueError:
        return "Unknown"


def is_failed_login(row):
    return row["status"] == "401" and "/login" in row["path"].lower()


def remove_empty_counts(counter):
    cleaned = {}

    for key, value in counter.items():
        if value > 0:
            cleaned[key] = value

    return Counter(cleaned)


def make_event(row, detection):
    geo = get_geo_info(row["ip"])

    return {
        "ip": row["ip"],
        "timestamp": row["timestamp"],
        "hour": get_hour(row["timestamp"]),
        "method": row["method"],
        "path": row["path"],
        "http_version": row["http_version"],
        "status": row["status"],
        "bytes": row["bytes"],
        "referrer": row.get("referrer") or "-",
        "user_agent": row.get("user_agent") or "-",
        "attack_type": detection["attack_type"],
        "severity": detection["severity"],
        "city": geo["city"],
        "country": geo["country"],
        "latitude": geo["latitude"],
        "longitude": geo["longitude"]
    }


def print_progress(done_bytes, total_bytes, total_logs, skipped_lines):
    done_mb = done_bytes / (1024 * 1024)
    total_mb = total_bytes / (1024 * 1024)

    if total_bytes == 0:
        percent = 0
    else:
        percent = (done_bytes / total_bytes) * 100

    print(
        f"Processed {done_mb:.1f} MB / {total_mb:.1f} MB "
        f"({percent:.1f}%) | Lines: {total_logs} | Skipped: {skipped_lines}"
    )


def check_cancel(cancel_check):
    if cancel_check is not None and cancel_check():
        raise AnalysisCancelled("Analysis cancelled")


def apply_brute_force_rule(
    failed_login_count,
    failed_login_old_attacks,
    failed_login_old_severity,
    failed_login_hours,
    failed_login_old_hour_attacks,
    attack_summary,
    severity_summary,
    top_attackers,
    attacks_per_hour
):
    brute_force_ips = set()

    for ip, count in failed_login_count.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            brute_force_ips.add(ip)

    for ip in brute_force_ips:
        failed_count = failed_login_count[ip]

        for old_attack, old_count in failed_login_old_attacks[ip].items():
            attack_summary[old_attack] -= old_count

            if old_attack != "NORMAL":
                top_attackers[ip] -= old_count

        for old_severity, old_count in failed_login_old_severity[ip].items():
            severity_summary[old_severity] -= old_count

        for hour, hour_count in failed_login_hours[ip].items():
            for old_attack, old_count in failed_login_old_hour_attacks[ip][hour].items():
                if old_attack != "NORMAL":
                    attacks_per_hour[hour] -= old_count

            attacks_per_hour[hour] += hour_count

        attack_summary["BRUTE_FORCE"] += failed_count
        severity_summary["HIGH"] += failed_count
        top_attackers[ip] += failed_count

    return brute_force_ips


def analyze_log_file(
    file_path,
    show_progress=False,
    progress_callback=None,
    cancel_check=None
):
    file_path = Path(file_path)
    total_bytes = file_path.stat().st_size

    done_bytes = 0
    next_progress = PROGRESS_STEP

    total_lines_seen = 0
    total_logs = 0
    skipped_lines = 0

    display_events = []

    attack_summary = Counter()
    severity_summary = Counter()
    top_attackers = Counter()
    attacks_per_hour = Counter()

    failed_login_count = Counter()
    failed_login_old_attacks = defaultdict(Counter)
    failed_login_old_severity = defaultdict(Counter)
    failed_login_hours = defaultdict(Counter)
    failed_login_old_hour_attacks = defaultdict(lambda: defaultdict(Counter))

    check_cancel(cancel_check)

    if show_progress:
        print("Starting log analysis")
        print("File:", file_path)
        print("Size:", round(total_bytes / (1024 * 1024), 2), "MB")
        print()

    with open(file_path, "rb") as log_file:
        for raw_line in log_file:
            total_lines_seen += 1
            done_bytes += len(raw_line)

            if total_lines_seen % CANCEL_CHECK_LINES == 0:
                check_cancel(cancel_check)

            line = raw_line.decode("utf-8", errors="ignore")
            match = re.search(LOG_PATTERN, line)

            if not match:
                skipped_lines += 1
            else:
                total_logs += 1

                row = match.groupdict()
                hour = get_hour(row["timestamp"])

                detection = detect_attack(row["path"])
                attack_type = detection["attack_type"]
                severity = detection["severity"]

                attack_summary[attack_type] += 1
                severity_summary[severity] += 1

                if attack_type != "NORMAL":
                    top_attackers[row["ip"]] += 1
                    attacks_per_hour[hour] += 1

                if is_failed_login(row):
                    ip = row["ip"]

                    failed_login_count[ip] += 1
                    failed_login_old_attacks[ip][attack_type] += 1
                    failed_login_old_severity[ip][severity] += 1
                    failed_login_hours[ip][hour] += 1
                    failed_login_old_hour_attacks[ip][hour][attack_type] += 1

                if len(display_events) < EVENT_LIMIT:
                    display_events.append(make_event(row, detection))

            if done_bytes >= next_progress:
                check_cancel(cancel_check)

                if show_progress:
                    print_progress(
                        done_bytes,
                        total_bytes,
                        total_logs,
                        skipped_lines
                    )

                if progress_callback is not None:
                    progress_callback(done_bytes, total_bytes)

                next_progress += PROGRESS_STEP

    check_cancel(cancel_check)

    brute_force_ips = apply_brute_force_rule(
        failed_login_count,
        failed_login_old_attacks,
        failed_login_old_severity,
        failed_login_hours,
        failed_login_old_hour_attacks,
        attack_summary,
        severity_summary,
        top_attackers,
        attacks_per_hour
    )

    attack_summary = remove_empty_counts(attack_summary)
    severity_summary = remove_empty_counts(severity_summary)
    top_attackers = remove_empty_counts(top_attackers)
    attacks_per_hour = remove_empty_counts(attacks_per_hour)

    for event in display_events:
        if event["ip"] in brute_force_ips:
            if event["status"] == "401" and "/login" in event["path"].lower():
                event["attack_type"] = "BRUTE_FORCE"
                event["severity"] = "HIGH"

    geo_locations = []

    for ip, count in top_attackers.most_common(50):
        geo = get_geo_info(ip)

        geo_locations.append({
            "ip": ip,
            "city": geo["city"],
            "country": geo["country"],
            "latitude": geo["latitude"],
            "longitude": geo["longitude"],
            "count": count
        })

    total_attacks = 0

    for attack_type, count in attack_summary.items():
        if attack_type != "NORMAL":
            total_attacks += count

    report = {
        "source_file": str(file_path),
        "file_size_mb": round(total_bytes / (1024 * 1024), 2),
        "total_logs": total_logs,
        "total_attacks": total_attacks,
        "skipped_lines": skipped_lines,
        "displayed_events": len(display_events),
        "event_display_limit": EVENT_LIMIT,
        "events_limited": total_logs > len(display_events),
        "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
        "geoip_status": get_geoip_status(),
        "attack_summary": dict(attack_summary),
        "severity_summary": dict(severity_summary),
        "top_attackers": dict(top_attackers.most_common(50)),
        "attacks_per_hour": [
            {
                "hour": hour,
                "count": count
            }
            for hour, count in sorted(attacks_per_hour.items())
        ],
        "geo_locations": geo_locations,
        "events": display_events
    }

    return report


def save_report(report, output_path="results.json"):
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)


if __name__ == "__main__":
    target_file = "sample.log"

    if len(sys.argv) >= 2:
        target_file = sys.argv[1]

    report = analyze_log_file(target_file, show_progress=True)
    save_report(report)

    print()
    print("Analysis complete")
    print("Source:", report["source_file"])
    print("Size MB:", report["file_size_mb"])
    print("GeoIP:", report["geoip_status"])
    print("Brute force threshold:", report["brute_force_threshold"])
    print("Total logs:", report["total_logs"])
    print("Total attacks:", report["total_attacks"])
    print("Skipped lines:", report["skipped_lines"])
    print("Displayed events:", report["displayed_events"])
    print("Events limited:", report["events_limited"])
    print("Attack summary:", report["attack_summary"])
    print("Severity summary:", report["severity_summary"])
    print("Top attackers:", report["top_attackers"])
    