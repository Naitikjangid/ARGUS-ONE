import json
import sys
from datetime import datetime, timedelta
from datetime import timezone

import requests

URL = "http://127.0.0.1:8001/api/flows"
TIMEOUT_SECONDS = 10
START_OFFSET = timedelta(minutes=5)
SCAN_INTERVAL = timedelta(milliseconds=250)

SOURCE_IP = "10.10.1.50"
TARGET_IP = "10.20.1.10"
SOURCE_PORT_START = 45000

common_ports = [
    21, 22, 23, 25, 53,
    80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432,
    5900, 8080, 8443, 9000, 9090,
    9200, 9300, 10000, 11211, 27017,
]

ports = common_ports + list(range(49152, 49307))


def iso_z(value):
    return value.isoformat().replace("+00:00", "Z")


def print_json(label, payload):
    print(f"{label}: {json.dumps(payload, separators=(',', ':'))}")


start_time = (
    datetime.now(timezone.utc).replace(microsecond=0)
    + START_OFFSET
)
sent_count = 0
all_alerts = []

print("=" * 70)
print("       ARGUS-ONE PORT SCANNING TEST")
print("=" * 70)
print(f"Endpoint: {URL}")
print(f"Flows:    {len(ports)}")

for i, port in enumerate(ports):

    flow = {
        "timestamp": iso_z(start_time + (SCAN_INTERVAL * i)),
        "src_ip": SOURCE_IP,
        "dst_ip": TARGET_IP,
        "src_port": SOURCE_PORT_START + i,
        "dst_port": port,
        "protocol": "TCP",
        "bytes_out": 0,
        "bytes_in": 0,
        "packets_out": 1,
        "packets_in": 0,
        "tcp_flags": "SYN",
    }

    try:
        print(
            f"\nFlow {i + 1:02d}/{len(ports)} | "
            f"{flow['src_ip']}:{flow['src_port']} -> "
            f"{flow['dst_ip']}:{flow['dst_port']}"
        )
        print_json("Request", flow)

        response = requests.post(
            URL,
            json=flow,
            timeout=TIMEOUT_SECONDS,
        )
        response_text = response.text

        try:
            response_body = response.json()
        except ValueError:
            response_body = {"raw_response": response_text}

        print(f"HTTP: {response.status_code}")
        print_json("Response", response_body)
        response.raise_for_status()

        if response_body.get("success") is not True:
            print("ERROR: Backend response did not include success=true.")
            sys.exit(1)

        sent_count += 1
        all_alerts.extend(response_body.get("alerts", []))

    except requests.exceptions.ConnectionError:
        print("\nERROR: Backend is not running.")
        print("Start it with:")
        print("python -m uvicorn backend.main:app")
        sys.exit(1)

    except requests.exceptions.HTTPError as error:
        print(f"\nERROR: HTTP request failed: {error}")
        sys.exit(1)

    except requests.exceptions.RequestException as error:
        print(f"\nERROR: Request failed: {error}")
        sys.exit(1)

port_scan_alerts = [
    alert
    for alert in all_alerts
    if alert.get("threat_class") == "Port Scanning"
]

print("\n" + "=" * 70)
print("Summary")
print("=" * 70)
print(f"Backend received {sent_count}/{len(ports)} flows successfully.")
print(f"Total alerts returned: {len(all_alerts)}")

if port_scan_alerts:
    print("ARGUS-ONE detected Port Scanning.")
    print_json("First Port Scanning alert", port_scan_alerts[0])
else:
    print("ARGUS-ONE did not return a Port Scanning alert.")

print("\n" + "=" * 70)
print("Port scanning test completed.")
print("=" * 70)
