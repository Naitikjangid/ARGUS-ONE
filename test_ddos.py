from datetime import datetime, timedelta, timezone

import requests


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


start = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=5)
flows = []
for i in range(429):
    if i % 13 < 3:
        flows.append(
            flow(
                start + timedelta(milliseconds=80 * i),
                f"198.51.100.{(i % 254) + 1}",
                "10.0.0.100",
                53,
                1024 + i,
                "UDP",
                2500 + (i % 10) * 100,
                100,
                2,
                1,
                "",
            )
        )
    else:
        flows.append(
            flow(
                start + timedelta(milliseconds=80 * i),
                f"203.0.113.{(i % 254) + 1}",
                "10.0.0.100",
                1024 + i,
                80,
                "TCP",
                0,
                0,
                1,
                0,
                "S",
            )
        )


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
print("Test: DDoS")
print(f"Total flows sent: {len(flows)}")
print(f"HTTP successful flows: {successful}")
print(f"Total alerts returned: {len(all_alerts)}")
print(f"Detected threat class: {first_alert.get('threat_class', 'None')}")
print(f"First alert risk score: {first_alert.get('risk_score', 'None')}")
print(f"Classification confidence: {first_alert.get('classification_confidence', 'None')}")
print(f"Anomaly confidence: {first_alert.get('anomaly_confidence', 'None')}")
print(f"Temporal confidence: {first_alert.get('detection_basis', {}).get('behavioral_ml', {}).get('temporal_confidence', 'None')}")
print(f"Errors: {errors if errors else 'None'}")
