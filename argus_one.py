"""ARGUS-ONE: passive metadata threat detection.

This module deliberately accepts *normalised flow metadata only*.  It neither
generates traffic nor reads/decrypts packet payloads.  Feed each collector
record to ``ArgusOneDetector.process_flow``; the return value is a list of
structured alerts suitable for a REST API, websocket, or dashboard.

Required fields: timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
bytes_out, bytes_in, packets_out, packets_in, tcp_flags.
Optional context keys: dns_metadata (query_name/query_type), tls_metadata
(ja3/ja3s/ja4/sni/alpn), quic_metadata, and destination_reputation.
"""
from __future__ import annotations

import argparse
import hashlib
import bisect
import ipaddress
import json
import math
import statistics
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Iterable, Mapping, Sequence


WINDOWS = (60, 300, 1800)
REQUIRED_FIELDS = {
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bytes_out", "bytes_in", "packets_out", "packets_in", "tcp_flags",
}
def _ratio(numerator: float, denominator: float) -> float:
    return float(numerator) / (float(denominator) + 1e-9)


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def entropy(values: Iterable[Any]) -> float:
    """Shannon entropy in bits, safely returning zero for no observations."""
    counts = Counter(values)
    total = sum(counts.values())
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) if total else 0.0


def normalised_entropy(values: Iterable[Any]) -> float:
    values = list(values)
    unique = len(set(values))
    return _ratio(entropy(values), math.log2(unique)) if unique > 1 else 0.0


def _prefix(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
        bits = 24 if address.version == 4 else 64
        return str(ipaddress.ip_network(f"{address}/{bits}", strict=False))
    except ValueError:
        return "invalid"


def _is_external(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # Do not silently discard collector aliases/hostnames.


def _median(values: Sequence[float]) -> float:
    return statistics.median(values) if values else 0.0


def _coefficient_of_variation(values: Sequence[float]) -> float:
    if len(values) < 2 or _median(values) <= 0:
        return 1.0
    return _ratio(statistics.pstdev(values), statistics.mean(values))


def _risk(score: float) -> str:
    return "critical" if score >= .90 else "high" if score >= .75 else "medium" if score >= .55 else "low"


@dataclass(frozen=True)
class Flow:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_out: int
    bytes_in: int
    packets_out: int
    packets_in: int
    tcp_flags: str
    context: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "Flow":
        missing = REQUIRED_FIELDS - raw.keys()
        if missing:
            raise ValueError(f"flow is missing required fields: {sorted(missing)}")
        timestamp = raw["timestamp"]
        if isinstance(timestamp, datetime):
            if timestamp.tzinfo is None:
                raise ValueError("timestamp datetime must include a timezone")
            timestamp = timestamp.timestamp()
        elif isinstance(timestamp, str):
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timestamp text must include a timezone")
            timestamp = parsed.timestamp()
        try:
            timestamp = float(timestamp)
        except (TypeError, ValueError) as exc:
            raise ValueError("timestamp must be Unix seconds, ISO-8601, or datetime") from exc
        if not math.isfinite(timestamp):
            raise ValueError("timestamp must be finite")
        for name in ("src_ip", "dst_ip"):
            try:
                ipaddress.ip_address(str(raw[name]))
            except ValueError as exc:
                raise ValueError(f"{name} must be a valid IPv4 or IPv6 address") from exc
        numbers = {}
        for key in ("src_port", "dst_port", "bytes_out", "bytes_in", "packets_out", "packets_in"):
            try:
                numbers[key] = max(0, int(raw[key]))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{key} must be a non-negative integer") from exc
        context = raw.get("context", {})
        if not isinstance(context, Mapping):
            raise ValueError("context must be an object when supplied")
        # Permit the earlier ARGUS-ONE top-level enrichment convention too.
        context = dict(context)
        for key in ("dns_metadata", "tls_metadata", "quic_metadata", "destination_reputation"):
            if key in raw and key not in context:
                context[key] = raw[key]
        return cls(timestamp, str(raw["src_ip"]), str(raw["dst_ip"]), protocol=str(raw["protocol"]).upper(),
                   tcp_flags=str(raw["tcp_flags"] or "").upper(), context=context, **numbers)

    @property
    def is_syn_only(self) -> bool:
        return self.protocol == "TCP" and "S" in self.tcp_flags and "A" not in self.tcp_flags

    @property
    def packet_size_out(self) -> float:
        return _ratio(self.bytes_out, self.packets_out)

    @property
    def packet_size_in(self) -> float:
        return _ratio(self.bytes_in, self.packets_in)


@dataclass(frozen=True)
class Finding:
    threat_class: str
    score: float
    source_ip: str
    target_ip: str
    detector: str
    evidence: tuple[dict[str, Any], ...]
    window_seconds: int


@dataclass
class DetectorConfig:
    syn_flows_per_second: float = 20.0
    udp_flows_per_second: float = 30.0
    scan_min_ports: int = 20
    scan_min_hosts: int = 12
    exfil_min_bytes: int = 10_000_000
    exfil_min_ratio: float = 12.0
    c2_min_observations: int = 5
    alert_cooldown_seconds: int = 30
    malicious_tls_fingerprints: set[str] = field(default_factory=set)
    trusted_tls_fingerprints: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, values: Mapping[str, Any]) -> "DetectorConfig":
        """Load only recognised, bounded detector configuration values."""
        numeric = (
            "syn_flows_per_second", "udp_flows_per_second", "scan_min_ports",
            "scan_min_hosts", "exfil_min_bytes", "exfil_min_ratio",
            "c2_min_observations", "alert_cooldown_seconds",
        )
        clean: dict[str, Any] = {}
        for name in numeric:
            if name in values:
                try:
                    clean[name] = float(values[name]) if "per_second" in name or "ratio" in name else int(values[name])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"configuration '{name}' must be numeric") from exc
        for name in ("malicious_tls_fingerprints", "trusted_tls_fingerprints"):
            supplied = values.get(name, [])
            if not isinstance(supplied, list) or not all(isinstance(item, str) for item in supplied):
                raise ValueError(f"configuration '{name}' must be a list of strings")
            clean[name] = {item.strip().lower() for item in supplied if item.strip()}
        config = cls(**clean)
        if min(config.syn_flows_per_second, config.udp_flows_per_second, config.exfil_min_bytes, config.exfil_min_ratio) <= 0:
            raise ValueError("rate, byte, and ratio thresholds must be positive")
        if min(config.scan_min_ports, config.scan_min_hosts, config.c2_min_observations, config.alert_cooldown_seconds) < 1:
            raise ValueError("minimum observation thresholds must be at least one")
        return config


def load_detector_config(path: str | Path) -> DetectorConfig:
    """Load a model-only JSON configuration without exposing arbitrary code."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("detector configuration must be a JSON object")
    return DetectorConfig.from_dict(raw)


class RollingFlowStore:
    """Thread-safe chronological store; retain only the largest analysis horizon."""
    def __init__(self, retention_seconds: int = max(WINDOWS)) -> None:
        self.retention_seconds = retention_seconds
        self._flows: Deque[Flow] = deque()
        self._latest_timestamp = float("-inf")
        self._lock = threading.RLock()

    def add(self, flow: Flow) -> bool:
        """Store an in-horizon flow chronologically; discard stale late arrivals."""
        with self._lock:
            self._latest_timestamp = max(self._latest_timestamp, flow.timestamp)
            cutoff = self._latest_timestamp - self.retention_seconds
            if flow.timestamp < cutoff:
                return False
            if not self._flows or flow.timestamp >= self._flows[-1].timestamp:
                self._flows.append(flow)
            else:
                timestamps = [item.timestamp for item in self._flows]
                self._flows.insert(bisect.bisect_right(timestamps, flow.timestamp), flow)
            while self._flows and self._flows[0].timestamp < cutoff:
                self._flows.popleft()
            return True

    def window(self, now: float, seconds: int, predicate: Callable[[Flow], bool] | None = None) -> list[Flow]:
        cutoff = now - seconds
        with self._lock:
            return [f for f in self._flows if f.timestamp >= cutoff and (predicate is None or predicate(f))]

    def all(self) -> list[Flow]:
        with self._lock:
            return list(self._flows)


class MetadataBaseline:
    """Benign-only robust baseline for unusual byte-ratio / flow-rate evidence.

    Call ``fit`` with a known-benign flow collection before production.  It is
    deliberately advisory: attack detectors never depend on it being trained.
    """
    def __init__(self) -> None:
        self.median: dict[str, float] = {}
        self.mad: dict[str, float] = {}

    def fit(self, flows: Iterable[Mapping[str, Any] | Flow]) -> "MetadataBaseline":
        rows = [f if isinstance(f, Flow) else Flow.from_mapping(f) for f in flows]
        if not rows:
            raise ValueError("at least one benign flow is required to fit a baseline")
        features = {
            "outbound_ratio": [_ratio(f.bytes_out, f.bytes_in + 1) for f in rows],
            "total_bytes": [float(f.bytes_out + f.bytes_in) for f in rows],
            "packets": [float(f.packets_out + f.packets_in) for f in rows],
        }
        for name, values in features.items():
            med = _median(values)
            self.median[name] = med
            self.mad[name] = max(_median([abs(v - med) for v in values]), 1.0)
        return self

    def z_score(self, name: str, value: float) -> float:
        if name not in self.median:
            return 0.0
        return abs(value - self.median[name]) / (1.4826 * self.mad[name])

    def to_dict(self) -> dict[str, dict[str, float]]:
        """Portable benign-baseline artefact for offline training/replay."""
        return {"median": self.median, "mad": self.mad}

    @classmethod
    def from_dict(cls, data: Mapping[str, Mapping[str, float]]) -> "MetadataBaseline":
        if not isinstance(data, Mapping) or not isinstance(data.get("median"), Mapping) or not isinstance(data.get("mad"), Mapping):
            raise ValueError("baseline must contain 'median' and 'mad' objects")
        baseline = cls()
        baseline.median = {str(k): float(v) for k, v in data.get("median", {}).items()}
        baseline.mad = {str(k): max(float(v), 1.0) for k, v in data.get("mad", {}).items()}
        return baseline


class ArgusOneDetector:
    """Independent, explainable detectors for passive flow metadata.

    No finding shares mutable model state with another detector.  That avoids
    a C2/DNS/exfiltration signal contaminating a DDoS or scan decision.
    """
    def __init__(self, config: DetectorConfig | None = None, baseline: MetadataBaseline | None = None) -> None:
        self.config = config or DetectorConfig()
        self.baseline = baseline or MetadataBaseline()
        self.store = RollingFlowStore()
        self._last_alert: dict[tuple[str, str, str], float] = {}
        self._last_evaluation: dict[tuple[str, str], float] = {}
        self._lock = threading.RLock()

    def process_flow(self, raw: Mapping[str, Any] | Flow) -> list[dict[str, Any]]:
        flow = raw if isinstance(raw, Flow) else Flow.from_mapping(raw)
        with self._lock:
            if not self.store.add(flow):
                return []  # stale collector record: never reopen an expired incident
            findings = (
                self._syn_flood(flow) + self._udp_reflection(flow) + self._spoofed_flood(flow)
                + self._c2_beacon(flow) + self._dns_anomalies(flow) + self._encrypted_malware(flow)
                + self._port_scan(flow) + self._exfiltration(flow)
            )
            return [self._alert(f, flow.timestamp) for f in findings if self._emit(f, flow.timestamp)]

    def process_batch(self, flows: Iterable[Mapping[str, Any] | Flow]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        for flow in sorted((f if isinstance(f, Flow) else Flow.from_mapping(f) for f in flows), key=lambda item: item.timestamp):
            alerts.extend(self.process_flow(flow))
        return alerts

    def _emit(self, finding: Finding, now: float) -> bool:
        key = (finding.threat_class, finding.source_ip, finding.target_ip)
        if now - self._last_alert.get(key, float("-inf")) < self.config.alert_cooldown_seconds:
            return False
        self._last_alert[key] = now
        return True

    def _due(self, detector: str, entity: str, now: float, interval: float) -> bool:
        """Bound aggregate work without suppressing per-flow ingestion."""
        key = (detector, entity)
        if now - self._last_evaluation.get(key, float("-inf")) < interval:
            return False
        self._last_evaluation[key] = now
        return True

    def _alert(self, finding: Finding, timestamp: float) -> dict[str, Any]:
        serial = f"{finding.threat_class}|{finding.source_ip}|{finding.target_ip}|{int(timestamp)}"
        return {
            "alert_id": "ALT-" + hashlib.sha256(serial.encode()).hexdigest()[:12].upper(),
            "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            "threat_class": finding.threat_class, "risk_score": round(finding.score, 3),
            "severity": _risk(finding.score), "source": {"ip": finding.source_ip},
            "target": {"ip": finding.target_ip}, "detector": finding.detector,
            "window_seconds": finding.window_seconds, "evidence": list(finding.evidence),
        }

    @staticmethod
    def _evidence(name: str, value: Any, threshold: Any, detail: str) -> dict[str, Any]:
        return {"feature": name, "value": round(value, 4) if isinstance(value, float) else value,
                "threshold": threshold, "detail": detail}

    def _syn_flood(self, flow: Flow) -> list[Finding]:
        if not flow.is_syn_only or not self._due("syn_flood", flow.dst_ip, flow.timestamp, 1):
            return []
        rows = self.store.window(flow.timestamp, 60, lambda f: f.dst_ip == flow.dst_ip and f.is_syn_only)
        rate = len(rows) / 60
        half_open = _ratio(sum(1 for f in rows if f.is_syn_only), sum(1 for f in self.store.window(flow.timestamp, 60, lambda f: f.dst_ip == flow.dst_ip and f.protocol == "TCP")))
        source_h = normalised_entropy([f.src_ip for f in rows])
        if rate < self.config.syn_flows_per_second or half_open < .70:
            return []
        score = _clamp(.45 + .30 * _clamp(rate / self.config.syn_flows_per_second - 1) + .15 * half_open + .10 * source_h)
        return [Finding("SYN Flood", score, "multiple" if source_h > .6 else flow.src_ip, flow.dst_ip, "syn_flood", (
            self._evidence("syn_flows_per_second", rate, self.config.syn_flows_per_second, "SYN-only rate toward one target"),
            self._evidence("half_open_ratio", half_open, .70, "SYNs not followed by acknowledgements"),
            self._evidence("source_ip_entropy_normalized", source_h, .0, "distributed sources increase confidence"),), 60)]

    def _udp_reflection(self, flow: Flow) -> list[Finding]:
        if flow.protocol != "UDP" or not self._due("udp_reflection", flow.dst_ip, flow.timestamp, 1):
            return []
        rows = self.store.window(flow.timestamp, 60, lambda f: f.protocol == "UDP" and f.dst_ip == flow.dst_ip)
        if not rows:
            return []
        rate = len(rows) / 60
        amplification = _ratio(sum(f.bytes_in for f in rows), sum(f.bytes_out for f in rows) + 1)
        reflectors = len({f.src_ip for f in rows})
        service_ports = len({f.src_port for f in rows if f.src_port in {53, 123, 1900, 389, 11211, 19}})
        if rate < self.config.udp_flows_per_second or (amplification < 3 and reflectors < 12):
            return []
        score = _clamp(.45 + .20 * _clamp(rate / self.config.udp_flows_per_second - 1) + .18 * _clamp(amplification / 10) + .10 * _clamp(reflectors / 30) + .07 * _clamp(service_ports / 3))
        return [Finding("UDP Reflection / Amplification", score, "multiple", flow.dst_ip, "udp_reflection", (
            self._evidence("udp_flows_per_second", rate, self.config.udp_flows_per_second, "high UDP rate to one victim"),
            self._evidence("inbound_outbound_byte_amplification", amplification, 3.0, "response bytes dominate requests"),
            self._evidence("distinct_reflectors", reflectors, 12, "many UDP sources target one victim"),
            self._evidence("amplifier_service_ports", service_ports, 1, "known reflection service ports observed"),), 60)]

    def _spoofed_flood(self, flow: Flow) -> list[Finding]:
        if not self._due("spoofed_source_flood", flow.dst_ip, flow.timestamp, 2):
            return []
        rows = self.store.window(flow.timestamp, 60, lambda f: f.dst_ip == flow.dst_ip)
        if len(rows) < 100:
            return []
        rate = len(rows) / 60
        ips = [f.src_ip for f in rows]
        ip_entropy, prefix_entropy = normalised_entropy(ips), normalised_entropy([_prefix(ip) for ip in ips])
        singleton_fraction = _ratio(sum(n == 1 for n in Counter(ips).values()), len(set(ips)))
        if rate < self.config.udp_flows_per_second or ip_entropy < .86 or singleton_fraction < .70:
            return []
        score = _clamp(.50 + .20 * ip_entropy + .15 * prefix_entropy + .15 * singleton_fraction)
        return [Finding("Spoofed-Source Flood", score, "multiple", flow.dst_ip, "spoofed_source_flood", (
            self._evidence("source_ip_entropy_normalized", ip_entropy, .86, "near-uniform source distribution"),
            self._evidence("source_prefix_entropy_normalized", prefix_entropy, .0, "sources span many network prefixes"),
            self._evidence("single_use_source_fraction", singleton_fraction, .70, "most sources appear once"),
            self._evidence("flows_per_second", rate, self.config.udp_flows_per_second, "high rate towards one target"),), 60)]

    def _c2_beacon(self, flow: Flow) -> list[Finding]:
        if flow.is_syn_only or flow.packets_in == 0 or not self._due("periodic_beacon", f"{flow.src_ip}|{flow.dst_ip}|{flow.dst_port}", flow.timestamp, 10):
            return []
        # A flood's repeated SYN retries can be mechanically periodic; C2 is
        # evaluated only on established/non-SYN-only flows to avoid that clash.
        rows = self.store.window(flow.timestamp, 1800, lambda f: f.src_ip == flow.src_ip and f.dst_ip == flow.dst_ip and f.dst_port == flow.dst_port and not f.is_syn_only)
        if len(rows) < self.config.c2_min_observations:
            return []
        rows.sort(key=lambda f: f.timestamp)
        iats = [b.timestamp - a.timestamp for a, b in zip(rows, rows[1:]) if 1 <= b.timestamp - a.timestamp <= 1800]
        if len(iats) < self.config.c2_min_observations - 1:
            return []
        cv = _coefficient_of_variation(iats)
        period = _median(iats)
        sizes = [f.bytes_out + f.bytes_in for f in rows]
        size_cv = _coefficient_of_variation(sizes)
        destinations = len({f.dst_ip for f in self.store.window(flow.timestamp, 1800, lambda f: f.src_ip == flow.src_ip)})
        if cv > .18 or not 5 <= period <= 1800 or destinations > 5:
            return []
        score = _clamp(.50 + .22 * (1 - cv / .18) + .14 * _clamp(1 - size_cv) + .14 * _clamp(len(rows) / 15))
        return [Finding("Botnet C2 Beaconing", score, flow.src_ip, flow.dst_ip, "periodic_beacon", (
            self._evidence("observation_count", len(rows), self.config.c2_min_observations, "repeated source/destination flow"),
            self._evidence("inter_arrival_cv", cv, .18, "low variance reveals periodic timing"),
            self._evidence("median_period_seconds", period, "5..1800", "estimated beacon interval"),
            self._evidence("destination_set_size", destinations, 5, "small destination set"),), 1800)]

    @staticmethod
    def _dns(flow: Flow) -> tuple[str, str] | None:
        metadata = flow.context.get("dns_metadata", {})
        if not isinstance(metadata, Mapping):
            return None
        query = str(metadata.get("query_name") or metadata.get("query") or "").strip(".").lower()
        record_type = str(metadata.get("query_type") or metadata.get("record_type") or "A").upper()
        return (query, record_type) if query else None

    @staticmethod
    def _label_entropy(label: str) -> float:
        chars = [c for c in label.lower() if c.isalnum()]
        return _ratio(entropy(chars), math.log2(min(len(set(chars)), 36))) if len(chars) > 2 and len(set(chars)) > 1 else 0.0

    def _dns_anomalies(self, flow: Flow) -> list[Finding]:
        parsed = self._dns(flow)
        if not parsed:
            return []
        query, record_type = parsed
        label = query.split(".")[0]
        q_entropy, length = self._label_entropy(label), len(query)
        digit_fraction = _ratio(sum(c.isdigit() for c in label), max(len(label), 1))
        # DGA uses a lightweight lexical model: length + entropy + digit density.
        dga = q_entropy >= .78 and len(label) >= 12 and digit_fraction >= .12
        rows = self.store.window(flow.timestamp, 300, lambda f: f.src_ip == flow.src_ip and self._dns(f) is not None)
        names = [self._dns(f)[0] for f in rows if self._dns(f)]
        unique_labels = len({n.split(".")[0] for n in names})
        txt_or_null = sum(self._dns(f)[1] in {"TXT", "NULL", "CNAME"} for f in rows if self._dns(f))
        tunnel = length >= 52 and q_entropy >= .72 and (txt_or_null >= 3 or unique_labels >= 12)
        findings: list[Finding] = []
        if dga:
            score = _clamp(.52 + .25 * _clamp((q_entropy - .78) / .22) + .13 * _clamp((len(label) - 12) / 25) + .10 * _clamp(digit_fraction / .35))
            findings.append(Finding("DGA Domain", score, flow.src_ip, flow.dst_ip, "dns_lexical", (
                self._evidence("leftmost_label_entropy_normalized", q_entropy, .78, "algorithmic-looking label"),
                self._evidence("leftmost_label_length", len(label), 12, "unusually long DGA-like label"),
                self._evidence("digit_fraction", digit_fraction, .12, "unusual alphanumeric composition"),), 300))
        if tunnel:
            score = _clamp(.55 + .18 * _clamp((length - 52) / 100) + .14 * _clamp((q_entropy - .72) / .28) + .13 * _clamp(max(txt_or_null / 5, unique_labels / 20)))
            findings.append(Finding("DNS Tunnelling", score, flow.src_ip, flow.dst_ip, "dns_tunnel", (
                self._evidence("query_length", length, 52, "long DNS query name"),
                self._evidence("leftmost_label_entropy_normalized", q_entropy, .72, "high-entropy encoded label"),
                self._evidence("unusual_record_type_count", txt_or_null, 3, "TXT/NULL/CNAME use in rolling window"),
                self._evidence("unique_subdomain_count", unique_labels, 12, "rapidly changing subdomains"),), 300))
        return findings

    @staticmethod
    def _fingerprint(flow: Flow) -> str:
        for container in (flow.context.get("tls_metadata", {}), flow.context.get("quic_metadata", {})):
            if isinstance(container, Mapping):
                for key in ("ja4", "ja3", "ja3s"):
                    if container.get(key):
                        return str(container[key]).lower()
        return ""

    def _encrypted_malware(self, flow: Flow) -> list[Finding]:
        fingerprint = self._fingerprint(flow)
        encrypted = flow.protocol in {"QUIC", "TLS"} or flow.dst_port in {443, 8443, 853} or bool(fingerprint)
        if not encrypted or flow.is_syn_only or flow.packets_in == 0 or not self._due("tls_quic_metadata", f"{flow.src_ip}|{flow.dst_ip}|{fingerprint}", flow.timestamp, 10):
            return []
        rows = self.store.window(flow.timestamp, 300, lambda f: f.src_ip == flow.src_ip and f.dst_ip == flow.dst_ip and self._fingerprint(f) == fingerprint)
        sizes = [f.bytes_out + f.bytes_in for f in rows]
        iats = [b.timestamp - a.timestamp for a, b in zip(rows, rows[1:]) if b.timestamp > a.timestamp]
        bad_fp = fingerprint in {x.lower() for x in self.config.malicious_tls_fingerprints}
        rare_fp = bool(fingerprint) and fingerprint not in {x.lower() for x in self.config.trusted_tls_fingerprints} and len(rows) <= 3
        sequence_regular = len(iats) >= 4 and _coefficient_of_variation(iats) < .20 and _coefficient_of_variation(sizes) < .35
        reputation = str(flow.context.get("destination_reputation", "")).lower()
        bad_destination = any(word in reputation for word in ("malicious", "suspicious", "high_risk"))
        if not (bad_fp or (sequence_regular and (rare_fp or bad_destination))):
            return []
        score = _clamp(.55 + .25 * bad_fp + .12 * sequence_regular + .08 * bad_destination)
        return [Finding("Encrypted-Session Malware", score, flow.src_ip, flow.dst_ip, "tls_quic_metadata", (
            self._evidence("fingerprint", fingerprint or "unavailable", "known-bad or rare", "JA3/JA3S/JA4 fingerprint metadata only"),
            self._evidence("known_malicious_fingerprint", bad_fp, True, "local threat-intel match"),
            self._evidence("packet_size_timing_sequence_regular", sequence_regular, True, "repeated encrypted-session metadata pattern"),
            self._evidence("destination_reputation_risk", bad_destination, True, "optional reputation enrichment"),), 300)]

    def _port_scan(self, flow: Flow) -> list[Finding]:
        if not self._due("fanout_scan", flow.src_ip, flow.timestamp, 2):
            return []
        rows = self.store.window(flow.timestamp, 60, lambda f: f.src_ip == flow.src_ip)
        ports, hosts = len({f.dst_port for f in rows}), len({f.dst_ip for f in rows})
        syn_ratio = _ratio(sum(f.is_syn_only for f in rows), len(rows))
        failed_ratio = _ratio(sum(f.is_syn_only and (f.bytes_in + f.packets_in == 0) for f in rows), len(rows))
        if ports < self.config.scan_min_ports and hosts < self.config.scan_min_hosts:
            return []
        if syn_ratio < .45 and failed_ratio < .35:
            return []
        score = _clamp(.48 + .20 * _clamp(ports / self.config.scan_min_ports) + .16 * _clamp(hosts / self.config.scan_min_hosts) + .09 * syn_ratio + .07 * failed_ratio)
        return [Finding("Port Scanning", score, flow.src_ip, "multiple" if hosts > 1 else flow.dst_ip, "fanout_scan", (
            self._evidence("unique_destination_ports", ports, self.config.scan_min_ports, "port fan-out from one source"),
            self._evidence("unique_destination_hosts", hosts, self.config.scan_min_hosts, "host fan-out from one source"),
            self._evidence("syn_only_ratio", syn_ratio, .45, "connection attempts dominate"),
            self._evidence("unanswered_attempt_ratio", failed_ratio, .35, "many connection attempts get no response"),), 60)]

    def _exfiltration(self, flow: Flow) -> list[Finding]:
        if not self._due("asymmetric_volume", flow.src_ip, flow.timestamp, 30):
            return []
        rows = self.store.window(flow.timestamp, 300, lambda f: f.src_ip == flow.src_ip and _is_external(f.dst_ip))
        out_bytes, in_bytes = sum(f.bytes_out for f in rows), sum(f.bytes_in for f in rows)
        ratio, total = _ratio(out_bytes, in_bytes + 1), out_bytes + in_bytes
        baseline_z = self.baseline.z_score("outbound_ratio", ratio)
        # Absolute floor prevents a single tiny request from looking suspicious.
        if out_bytes < self.config.exfil_min_bytes or ratio < self.config.exfil_min_ratio:
            return []
        score = _clamp(.52 + .18 * _clamp(math.log10(out_bytes / self.config.exfil_min_bytes + 1)) + .18 * _clamp(ratio / (2 * self.config.exfil_min_ratio)) + .12 * _clamp(baseline_z / 6))
        target = max(rows, key=lambda f: f.bytes_out).dst_ip if rows else flow.dst_ip
        return [Finding("Data Exfiltration", score, flow.src_ip, target, "asymmetric_volume", (
            self._evidence("outbound_bytes", out_bytes, self.config.exfil_min_bytes, "large external outbound volume"),
            self._evidence("outbound_inbound_byte_ratio", ratio, self.config.exfil_min_ratio, "outbound volume strongly exceeds replies"),
            self._evidence("baseline_robust_z_score", baseline_z, 3.0, "optional benign baseline deviation"),
            self._evidence("total_bytes", total, self.config.exfil_min_bytes, "five-minute flow volume"),), 300)]


def demo_flows(now: float | None = None) -> list[dict[str, Any]]:
    """Safe synthetic metadata for a smoke test; it emits no network traffic."""
    now = now or time.time()
    flows: list[dict[str, Any]] = []
    def add(**values: Any) -> None:
        flows.append({"timestamp": now + values.pop("offset"), "src_port": 51000, "dst_port": 443,
                      "protocol": "TCP", "bytes_out": 60, "bytes_in": 0, "packets_out": 1,
                      "packets_in": 0, "tcp_flags": "S", **values})
    for i in range(1_300):
        add(offset=i / 25, src_ip=f"198.51.100.{i % 250 + 1}", dst_ip="10.0.0.20")
    for i in range(2_100):
        add(offset=55 + i / 40, src_ip=f"192.0.2.{i % 80 + 1}", dst_ip="10.0.0.22", src_port=53,
            dst_port=43000 + i % 1000, protocol="UDP", tcp_flags="", bytes_out=50, bytes_in=1400,
            packets_out=1, packets_in=2)
    for i in range(2_100):
        add(offset=115 + i / 40, src_ip=f"198.18.{i // 256}.{i % 256}", dst_ip="10.0.0.23", tcp_flags="A",
            bytes_out=90, bytes_in=0)
    for i in range(30):
        add(offset=60 + i, src_ip="10.0.0.50", dst_ip="10.0.0.30", dst_port=1000 + i)
    for i in range(6):
        add(offset=100 + 30 * i, src_ip="10.0.0.60", dst_ip="203.0.113.9", tcp_flags="A", bytes_out=220, bytes_in=160, packets_in=1)
    for i in range(5):
        add(offset=280 + 8 * i, src_ip="10.0.0.61", dst_ip="8.8.4.4", tcp_flags="A", bytes_out=300, bytes_in=500,
            packets_in=1, context={"tls_metadata": {"ja4": "rare-demo-ja4"}, "destination_reputation": "suspicious"})
    add(offset=300, src_ip="10.0.0.70", dst_ip="8.8.8.8", dst_port=53, protocol="UDP", tcp_flags="",
        context={"dns_metadata": {"query_name": "m3k4j8n2q7v6x9z5.example.net", "query_type": "A"}})
    for i in range(16):
        add(offset=305 + i, src_ip="10.0.0.80", dst_ip="1.1.1.1", dst_port=53, protocol="UDP", tcp_flags="",
            context={"dns_metadata": {"query_name": f"{('ab39xz' * 12)}{i}.tunnel.example", "query_type": "TXT"}})
    add(offset=330, src_ip="10.0.0.90", dst_ip="9.9.9.9", tcp_flags="A", bytes_out=14_000_000, bytes_in=3000)
    return flows


def main() -> None:
    parser = argparse.ArgumentParser(description="Run safe ARGUS-ONE metadata demonstration")
    parser.add_argument("--demo", action="store_true", help="process synthetic metadata and print alerts")
    parser.add_argument("--input", help="newline-delimited normalised flow JSON file")
    args = parser.parse_args()
    detector = ArgusOneDetector()
    if args.demo:
        alerts = detector.process_batch(demo_flows())
    elif args.input:
        with open(args.input, encoding="utf-8") as handle:
            alerts = detector.process_batch(json.loads(line) for line in handle if line.strip())
    else:
        parser.error("use --demo or --input FILE")
    print(json.dumps(alerts, indent=2))


if __name__ == "__main__":
    main()
