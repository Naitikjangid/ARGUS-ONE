import random

import numpy as np

import requests
from detector.argus_detector import generate_benign_flows, _as_dicts


URL = "http://127.0.0.1:8001/api/flows"
TIMEOUT_SECONDS = 10


def flow(timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
         bytes_out, bytes_in, packets_out, packets_in, tcp_flags):
    return {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "packets_out": packets_out,
        "packets_in": packets_in,
        "tcp_flags": tcp_flags,
    }


random.seed(42)
np.random.seed(42)
generated = _as_dicts(generate_benign_flows(700, 120))
generated.sort(key=lambda item: item["timestamp"])
flows = [
    flow(
        item["timestamp"],
        item["src_ip"],
        item["dst_ip"],
        item["src_port"],
        item["dst_port"],
        item["protocol"],
        item["bytes_out"],
        item["bytes_in"],
        item["packets_out"],
        item["packets_in"],
        item["tcp_flags"],
    )
    for item in generated
]


all_alerts = []
successful = 0
errors = []
for item in flows:
    try:
        response = requests.post(URL, json=item, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        body = response.json()
        if body.get("success") is not True:
            errors.append("Backend response did not include success=true.")
            continue
        successful += 1
        all_alerts.extend(body.get("alerts", []))
    except requests.RequestException as error:
        errors.append(str(error))
    except ValueError as error:
        errors.append(f"Invalid JSON response: {error}")


first_alert = all_alerts[0] if all_alerts else {}
print("Test: benign")
print(f"Total flows sent: {len(flows)}")
print(f"HTTP successful flows: {successful}")
print(f"Total alerts returned: {len(all_alerts)}")
print(f"Detected threat class: {first_alert.get('threat_class', 'None')}")
print(f"First alert risk score: {first_alert.get('risk_score', 'None')}")
print(f"Classification confidence: {first_alert.get('classification_confidence', 'None')}")
print(f"Anomaly confidence: {first_alert.get('anomaly_confidence', 'None')}")
print(f"Temporal confidence: {first_alert.get('detection_basis', {}).get('behavioral_ml', {}).get('temporal_confidence', 'None')}")
print(f"Errors: {errors if errors else 'None'}")
