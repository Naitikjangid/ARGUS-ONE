"""ARGUS-ONE Hybrid -- passive metadata threat detection.

This is a self-contained replacement for the detector/training part of the
original demo. It deliberately does not generate or inspect packet payloads.
It accepts normalized flow records from a passive, one-way collector.

Key changes:
* three concurrent horizons (60 s, 5 min, 30 min);
* robust-prototype classifier plus benign-only anomaly guard;
* temporal-consensus and cross-horizon features;
* adaptive event correlation;
* interactive local dashboard;
* Stop Simulation button;
* Clear Alerts button.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import threading
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import numpy as np
import pandas as pd


LABELS = ("Benign", "DDoS", "Botnet C2 Beaconing", "Port Scanning")
ATTACK_LABELS = LABELS[1:]
WINDOWS = (60, 300, 1800)

REQUIRED_FLOW_FIELDS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes_out",
    "bytes_in",
    "packets_out",
    "packets_in",
    "tcp_flags",
}

CONTEXT_FIELDS = (
    "asset_identity",
    "known_services",
    "user_device_role",
    "historical_behavior",
    "destination_reputation",
    "dns_metadata",
    "authentication_events",
)

CONTEXT_VALUE_LIMIT = 512


def _bounded_context_value(value: Any) -> Any:
    """Keep optional enrichment JSON-safe and bounded for alert output."""
    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return value[:CONTEXT_VALUE_LIMIT]

    if isinstance(value, dict):
        return {
            str(key)[:64]: _bounded_context_value(item)
            for key, item in list(value.items())[:32]
        }

    if isinstance(value, (list, tuple, set)):
        return [
            _bounded_context_value(item)
            for item in list(value)[:32]
        ]

    return str(value)[:CONTEXT_VALUE_LIMIT]


def _normalize_context(flow: dict[str, Any]) -> dict[str, Any]:
    """Read optional deployment enrichment without making it mandatory."""
    supplied = flow.get("context")
    context = dict(supplied) if isinstance(supplied, dict) else {}

    legacy_mapping = {
        "dns_query": "dns_metadata",
        "tls_fingerprint": "destination_reputation",
    }

    for legacy_key, context_key in legacy_mapping.items():
        if legacy_key in flow and flow[legacy_key] not in (None, ""):
            context.setdefault(legacy_key, flow[legacy_key])

    return {
        key: _bounded_context_value(context[key])
        for key in CONTEXT_FIELDS
        if key in context and context[key] not in (None, "")
    }


def _entropy(values: pd.Series) -> float:
    """Shannon entropy, returning zero for an empty series."""
    probabilities = values.value_counts(normalize=True)
    return (
        float(-(probabilities * np.log2(probabilities)).sum())
        if len(probabilities)
        else 0.0
    )


def _safe_div(numerator: float, denominator: float) -> float:
    return float(numerator) / (float(denominator) + 1e-9)


def validate_flow(flow: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize an untrusted collector record."""
    missing = REQUIRED_FLOW_FIELDS - flow.keys()

    if missing:
        raise ValueError(
            f"flow is missing required fields: {sorted(missing)}"
        )

    output = dict(flow)

    output["timestamp"] = pd.to_datetime(
        output["timestamp"],
        utc=True,
    )

    if pd.isna(output["timestamp"]):
        raise ValueError("timestamp is invalid")

    for key in (
        "src_port",
        "dst_port",
        "bytes_out",
        "bytes_in",
        "packets_out",
        "packets_in",
    ):
        output[key] = max(0, int(output[key]))

    output["protocol"] = str(output["protocol"]).upper()
    output["tcp_flags"] = str(output["tcp_flags"] or "")
    output["context"] = _normalize_context(output)

    return output


def _iat_features(frame: pd.DataFrame) -> tuple[float, float, float]:
    """Return mean IAT, coefficient of variation, and periodicity strength."""

    iats: list[float] = []

    for _, group in frame.sort_values("timestamp").groupby(
        ["src_ip", "dst_ip", "dst_port"]
    ):
        values = (
            group["timestamp"]
            .diff()
            .dt.total_seconds()
            .dropna()
            .to_numpy()
        )

        iats.extend(
            values[
                (values >= 0) &
                (values < 86400)
            ].tolist()
        )

    if not iats:
        return 0.0, 0.0, 0.0

    values = np.asarray(iats, dtype=float)

    mean = float(values.mean())
    cv = _safe_div(float(values.std()), mean)

    periodicity = (
        float(np.clip(1.0 - cv, 0.0, 1.0))
        if len(values) >= 3
        else 0.0
    )

    return mean, cv, periodicity


def window_features(
    frame: pd.DataFrame,
    seconds: int,
) -> dict[str, float]:
    """Extract payload-free behavioural features for one temporal horizon."""

    if frame.empty:
        return {"flow_count": 0.0}

    total_flows = len(frame)

    bytes_out = float(frame["bytes_out"].sum())
    bytes_in = float(frame["bytes_in"].sum())

    packets_out = float(frame["packets_out"].sum())
    packets_in = float(frame["packets_in"].sum())

    syn = float(
        frame["tcp_flags"]
        .str.contains("S", regex=False, na=False)
        .sum()
    )

    ack = float(
        frame["tcp_flags"]
        .str.contains("A", regex=False, na=False)
        .sum()
    )

    udp = float(
        (frame["protocol"] == "UDP").sum()
    )

    src_count = float(frame["src_ip"].nunique())
    dst_count = float(frame["dst_ip"].nunique())
    port_count = float(frame["dst_port"].nunique())

    mean_iat, cv_iat, periodicity = _iat_features(frame)

    destination_share = float(
        frame["dst_ip"]
        .value_counts(normalize=True)
        .iloc[0]
    ) if len(frame["dst_ip"].unique()) > 0 else 0.0

    peer_share = float(
        frame.groupby(["src_ip", "dst_ip"])
        .size()
        .max()
        / total_flows
    ) if total_flows > 0 else 0.0
    
    # Enhanced packet size distribution features
    avg_packet_size_out = _safe_div(
        bytes_out,
        packets_out,
    ) if packets_out > 0 else 0.0
    
    avg_packet_size_in = _safe_div(
        bytes_in,
        packets_in,
    ) if packets_in > 0 else 0.0
    
    # Protocol distribution
    tcp_ratio = _safe_div(
        float((frame["protocol"] == "TCP").sum()),
        total_flows,
    )
    
    # Enhanced entropy for port distribution
    src_port_entropy = _entropy(
        frame["src_port"].astype(str)
    )

    return {
        "flow_count": float(total_flows),
        "flows_per_second": _safe_div(total_flows, seconds),
        "bytes_per_second": _safe_div(
            bytes_out + bytes_in,
            seconds,
        ),
        "packets_per_second": _safe_div(
            packets_out + packets_in,
            seconds,
        ),
        "outbound_byte_ratio": _safe_div(
            bytes_out,
            bytes_out + bytes_in,
        ),
        "syn_ratio": _safe_div(
            syn,
            total_flows,
        ),
        "half_open_ratio": _safe_div(
            max(0.0, syn - ack),
            syn,
        ),
        "udp_ratio": _safe_div(
            udp,
            total_flows,
        ),
        "unique_sources": src_count,
        "unique_destinations": dst_count,
        "unique_destination_ports": port_count,
        "source_entropy": _entropy(frame["src_ip"]),
        "destination_port_entropy": _entropy(
            frame["dst_port"].astype(str)
        ),
        "destination_concentration": destination_share,
        "peer_concentration": peer_share,
        "port_fanout_per_source": _safe_div(
            port_count,
            src_count,
        ),
        "host_fanout_per_source": _safe_div(
            dst_count,
            src_count,
        ),
        "mean_iat": mean_iat,
        "iat_cv": cv_iat,
        "periodicity": periodicity,
        "avg_packet_size_out": avg_packet_size_out,
        "avg_packet_size_in": avg_packet_size_in,
        "tcp_ratio": tcp_ratio,
        "src_port_entropy": src_port_entropy,
    }


def multiscale_features(
    flows: Iterable[dict[str, Any]],
    now: pd.Timestamp,
) -> dict[str, float]:
    """Features across short, medium and long horizons."""

    frame = pd.DataFrame(list(flows))
    result: dict[str, float] = {}

    if frame.empty:
        return result

    for seconds in WINDOWS:
        current = frame.loc[
            frame["timestamp"]
            >= now - pd.Timedelta(seconds=seconds)
        ]

        result.update(
            {
                f"w{seconds}_{name}": value
                for name, value in window_features(
                    current,
                    seconds,
                ).items()
            }
        )

    result["burst_ratio_60_300"] = _safe_div(
        result["w60_flows_per_second"],
        result["w300_flows_per_second"],
    )

    result["persistence_ratio_300_1800"] = _safe_div(
        result["w300_flows_per_second"],
        result["w1800_flows_per_second"],
    )

    result["periodicity_consensus"] = float(
        np.mean(
            [
                result[f"w{s}_periodicity"]
                for s in WINDOWS
            ]
        )
    )

    result["fanout_growth"] = _safe_div(
        result["w60_unique_destination_ports"],
        result["w300_unique_destination_ports"],
    )

    return result


def context_summary(
    frame: pd.DataFrame,
) -> dict[str, Any]:
    """Summarize optional enrichment attached to flows in a window."""
    summary: dict[str, Any] = {}

    if frame.empty or "context" not in frame:
        return summary

    contexts = [
        context
        for context in frame["context"]
        if isinstance(context, dict)
    ]

    for field in CONTEXT_FIELDS:
        values = [
            context[field]
            for context in contexts
            if field in context
        ]

        if not values:
            continue

        summary[field] = _bounded_context_value(values[-1])

        if field in {
            "asset_identity",
            "user_device_role",
            "destination_reputation",
        }:
            summary[f"{field}_observations"] = len(
                {
                    json.dumps(value, sort_keys=True)
                    for value in values
                }
            )

    return summary


def identify_context(
    context: dict[str, Any],
) -> dict[str, Any]:
    """Identify available metadata and simple corroborating signals."""
    available = [
        field
        for field in CONTEXT_FIELDS
        if field in context and context[field] not in (None, "")
    ]
    missing = [
        field
        for field in CONTEXT_FIELDS
        if field not in available
    ]
    signals: list[str] = []

    history = context.get("historical_behavior")
    if isinstance(history, dict):
        baseline = str(history.get("baseline", "")).lower()
        if baseline in {"normal", "expected", "known"}:
            signals.append("matches_historical_baseline")
        elif baseline in {"unusual", "anomalous", "deviant"}:
            signals.append("deviates_from_historical_baseline")

    reputation = context.get("destination_reputation")
    if isinstance(reputation, dict):
        category = str(
            reputation.get("category", "")
        ).lower()
        if category in {"malicious", "suspicious", "high_risk"}:
            signals.append("destination_reputation_risk")
        elif category in {"benign", "trusted", "allowlisted"}:
            signals.append("destination_reputation_trusted")

    authentication = context.get("authentication_events")
    if isinstance(authentication, list):
        failures = sum(
            isinstance(event, dict)
            and str(event.get("result", "")).lower()
            in {"failure", "failed", "denied"}
            for event in authentication
        )
        if failures:
            signals.append("authentication_failures_present")

    return {
        "coverage": round(
            len(available) / len(CONTEXT_FIELDS),
            3,
        ),
        "available_fields": available,
        "missing_fields": missing,
        "signals": signals,
    }


class RobustPrototypeModel:
    """Custom robust classifier using median/MAD feature space."""

    def __init__(self) -> None:
        self.features: list[str] = []
        self.median: dict[str, np.ndarray] = {}
        self.scale: dict[str, np.ndarray] = {}
        self.temperature = 1.0

    @staticmethod
    def _transform(values: np.ndarray) -> np.ndarray:
        return np.sign(values) * np.log1p(np.abs(values))

    def fit(
        self,
        X: pd.DataFrame,
        y: list[str],
    ) -> "RobustPrototypeModel":

        self.features = list(X.columns)

        values = self._transform(
            X[self.features].to_numpy(dtype=float)
        )

        y_array = np.asarray(y)

        for label in LABELS:
            group = values[y_array == label]

            if len(group) == 0:
                raise ValueError(
                    f"no training samples for {label}"
                )

            median = np.median(group, axis=0)

            mad = np.median(
                np.abs(group - median),
                axis=0,
            )

            self.median[label] = median

            self.scale[label] = np.maximum(
                1.4826 * mad,
                0.08,
            )

        # Improved temperature calibration based on data spread
        mean_scale = np.mean(list(self.scale.values()))
        self.temperature = np.clip(
            1.2 + (mean_scale * 0.5),
            1.0,
            2.5,
        )

        return self

    def _distances(
        self,
        X: pd.DataFrame,
    ) -> np.ndarray:

        values = self._transform(
            X.reindex(
                columns=self.features,
                fill_value=0.0,
            ).to_numpy(dtype=float)
        )

        distances = []

        for label in LABELS:
            z = np.abs(
                (
                    values
                    - self.median[label]
                )
                / self.scale[label]
            )

            # Improved clipping and weighting
            # Emphasize deviations more for better discrimination
            clipped = np.minimum(z, 5.0)
            distances.append(
                np.mean(clipped, axis=1) * 1.1
            )

        return np.column_stack(distances)

    def predict_proba(
        self,
        X: pd.DataFrame,
    ) -> np.ndarray:

        distances = self._distances(X)

        logits = (
            -distances
            / self.temperature
        )

        logits -= logits.max(
            axis=1,
            keepdims=True,
        )

        exp = np.exp(logits)

        return exp / exp.sum(
            axis=1,
            keepdims=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "features": self.features,
            "median": {
                k: v.tolist()
                for k, v in self.median.items()
            },
            "scale": {
                k: v.tolist()
                for k, v in self.scale.items()
            },
            "temperature": self.temperature,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "RobustPrototypeModel":

        model = cls()

        model.features = data["features"]

        model.median = {
            k: np.asarray(v)
            for k, v in data["median"].items()
        }

        model.scale = {
            k: np.asarray(v)
            for k, v in data["scale"].items()
        }

        model.temperature = float(
            data["temperature"]
        )

        return model


class BenignAnomalyGuard:
    """Custom benign-only anomaly guard."""

    def __init__(self) -> None:
        self.features: list[str] = []
        self.median: np.ndarray | None = None
        self.scale: np.ndarray | None = None
        self.threshold = 0.0
        self.spread = 1.0

    def fit(
        self,
        X: pd.DataFrame,
    ) -> "BenignAnomalyGuard":

        self.features = list(X.columns)

        values = RobustPrototypeModel._transform(
            X.to_numpy(dtype=float)
        )

        self.median = np.median(
            values,
            axis=0,
        )

        self.scale = np.maximum(
            1.4826
            * np.median(
                np.abs(
                    values
                    - self.median
                ),
                axis=0,
            ),
            0.08,
        )

        scores = self.raw_score(X)

        # More aggressive threshold for better sensitivity
        self.threshold = float(
            np.quantile(
                scores,
                0.97,
            )
        )

        self.spread = max(
            float(
                np.quantile(
                    scores,
                    0.998,
                )
                - self.threshold
            ),
            0.15,
        )

        return self

    def raw_score(
        self,
        X: pd.DataFrame,
    ) -> np.ndarray:

        assert (
            self.median is not None
            and self.scale is not None
        )

        values = RobustPrototypeModel._transform(
            X.reindex(
                columns=self.features,
                fill_value=0.0,
            ).to_numpy(dtype=float)
        )

        # Improved sensitivity with lower clipping threshold
        return np.mean(
            np.minimum(
                np.abs(
                    (
                        values
                        - self.median
                    )
                    / self.scale
                ),
                7.0,
            ),
            axis=1,
        )

    def confidence(
        self,
        X: pd.DataFrame,
    ) -> np.ndarray:

        return np.clip(
            (
                self.raw_score(X)
                - self.threshold
            )
            / self.spread,
            0.0,
            1.0,
        )

    def to_dict(self) -> dict[str, Any]:
        assert (
            self.median is not None
            and self.scale is not None
        )

        return {
            "features": self.features,
            "median": self.median.tolist(),
            "scale": self.scale.tolist(),
            "threshold": self.threshold,
            "spread": self.spread,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "BenignAnomalyGuard":

        guard = cls()

        guard.features = data["features"]

        guard.median = np.asarray(
            data["median"]
        )

        guard.scale = np.asarray(
            data["scale"]
        )

        guard.threshold = float(
            data["threshold"]
        )

        guard.spread = float(
            data["spread"]
        )

        return guard


class ArgusFusionModel:
    """Fusion of classification, anomaly and temporal evidence."""

    def __init__(
        self,
        classifier: RobustPrototypeModel,
        anomaly_guard: BenignAnomalyGuard,
    ) -> None:

        self.classifier = classifier
        self.anomaly_guard = anomaly_guard

    def assess(
        self,
        features: dict[str, float],
    ) -> dict[str, Any]:

        X = pd.DataFrame([features])

        probabilities = (
            self.classifier.predict_proba(X)[0]
        )

        probability_by_label = dict(
            zip(
                LABELS,
                map(float, probabilities),
            )
        )

        best_attack = max(
            ATTACK_LABELS,
            key=probability_by_label.get,
        )

        classification = (
            probability_by_label[best_attack]
        )

        anomaly = float(
            self.anomaly_guard.confidence(X)[0]
        )

        temporal = float(
            np.clip(
                (
                    features.get(
                        "periodicity_consensus",
                        0.0,
                    )
                    + min(
                        features.get(
                            "burst_ratio_60_300",
                            0.0,
                        ),
                        2.0,
                    )
                    / 2.0
                    + min(
                        features.get(
                            "fanout_growth",
                            0.0,
                        ),
                        2.0,
                    )
                    / 2.0
                )
                / 3.0,
                0.0,
                1.0,
            )
        )

        # Improved risk weighting with better balance
        risk = (
            0.50 * classification
            + 0.35 * anomaly
            + 0.15 * temporal
        )

        # Enhanced alerting thresholds
        is_alert = (
            risk >= 0.58
            and (
                classification >= 0.38
                or anomaly >= 0.70
            )
        )

        # Better novel anomaly detection
        if (
            anomaly >= 0.88
            and classification < 0.38
        ):
            best_attack = "Novel Metadata Anomaly"
            is_alert = True

        return {
            "threat_class": best_attack,
            "risk": float(risk),
            "classification_confidence": classification,
            "anomaly_confidence": anomaly,
            "temporal_confidence": temporal,
            "is_alert": bool(is_alert),
            "probabilities": probability_by_label,
        }

    def save(self, path: Path) -> None:
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "classifier": self.classifier.to_dict(),
                    "anomaly_guard": self.anomaly_guard.to_dict(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(
        cls,
        path: Path,
    ) -> "ArgusFusionModel":

        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        return cls(
            RobustPrototypeModel.from_dict(
                data["classifier"]
            ),
            BenignAnomalyGuard.from_dict(
                data["anomaly_guard"]
            ),
        )


@dataclass
class AlertEpisode:
    maximum_risk: float
    last_risk: float
    last_seen: float
    fingerprint: str
    count: int = 1


class AdaptiveEventCorrelator:
    """Risk-decay event correlator."""

    def __init__(
        self,
        half_life_seconds: float = 120.0,
    ) -> None:

        self.half_life_seconds = (
            half_life_seconds
        )

        self.episodes: dict[
            str,
            AlertEpisode,
        ] = {}

    @staticmethod
    def _group_key(
        threat: str,
        last: dict[str, Any],
    ) -> str:

        if threat == "DDoS":
            return (
                f"{threat}:{last['dst_ip']}"
            )

        if threat == "Port Scanning":
            return (
                f"{threat}:{last['src_ip']}"
            )

        return (
            f"{threat}:"
            f"{last['src_ip']}:"
            f"{last['dst_ip']}"
        )

    @staticmethod
    def _evidence_fingerprint(
        evidence: dict[str, Any],
    ) -> str:

        bucketed = {}

        for key in (
            "w60_flow_count",
            "w60_port_fanout_per_source",
            "w1800_host_fanout_per_source",
        ):
            numeric = max(
                0.0,
                float(
                    evidence.get(
                        key,
                        0.0,
                    )
                ),
            )

            bucketed[key] = int(
                math.log2(
                    numeric + 1.0
                )
            )

        return hashlib.sha256(
            json.dumps(
                bucketed,
                sort_keys=True,
            ).encode()
        ).hexdigest()[:16]

    def decide(
        self,
        assessment: dict[str, Any],
        evidence: dict[str, Any],
        last: dict[str, Any],
        now: pd.Timestamp,
    ) -> str | None:

        threat = assessment["threat_class"]
        risk = assessment["risk"]

        key = self._group_key(
            threat,
            last,
        )

        fingerprint = (
            self._evidence_fingerprint(
                evidence
            )
        )

        now_seconds = now.timestamp()

        episode = self.episodes.get(key)

        if episode is None:

            self.episodes[key] = AlertEpisode(
                risk,
                risk,
                now_seconds,
                fingerprint,
            )

            return "new"

        elapsed = max(
            0.0,
            now_seconds
            - episode.last_seen,
        )

        decayed_peak = (
            episode.maximum_risk
            * math.pow(
                0.5,
                elapsed
                / self.half_life_seconds,
            )
        )

        materially_changed = (
            fingerprint
            != episode.fingerprint
        )

        # Improved escalation detection - more sensitive
        escalated = (
            risk
            >= max(
                decayed_peak + 0.06,
                episode.last_risk + 0.03,
            )
        )

        episode.maximum_risk = max(
            decayed_peak,
            risk,
        )

        episode.last_risk = risk
        episode.last_seen = now_seconds
        episode.fingerprint = fingerprint
        episode.count += 1

        return (
            "escalated"
            if escalated
            else (
                "changed"
                if materially_changed
                else None
            )
        )


class ArgusOneDetector:
    """Thread-safe streaming detector."""

    def __init__(
        self,
        model: ArgusFusionModel,
        max_lateness_seconds: int = 10,
        evaluation_every_flows: int = 5,
    ) -> None:

        self.model = model
        self.max_lateness_seconds = (
            max_lateness_seconds
        )

        if evaluation_every_flows < 1:
            raise ValueError(
                "evaluation_every_flows must be at least 1"
            )

        self.evaluation_every_flows = (
            evaluation_every_flows
        )

        self.flows: deque[
            dict[str, Any]
        ] = deque()

        self.received_flows = 0
        self.latest_timestamp: pd.Timestamp | None = None

        self.alerts: deque[
            dict[str, Any]
        ] = deque(maxlen=500)

        self.correlator = (
            AdaptiveEventCorrelator()
        )

        self.lock = threading.RLock()

    def process_flow(
        self,
        raw_flow: dict[str, Any],
    ) -> list[dict[str, Any]]:

        flow = validate_flow(raw_flow)

        with self.lock:

            if (
                self.latest_timestamp
                and flow["timestamp"]
                < self.latest_timestamp
                - pd.Timedelta(
                    seconds=self.max_lateness_seconds
                )
            ):
                return []

            self.latest_timestamp = (
                max(
                    self.latest_timestamp,
                    flow["timestamp"],
                )
                if self.latest_timestamp
                else flow["timestamp"]
            )

            if (
                not self.flows
                or flow["timestamp"]
                >= self.flows[-1]["timestamp"]
            ):
                self.flows.append(flow)

            else:

                insert_at = 0

                for index in range(
                    len(self.flows) - 1,
                    -1,
                    -1,
                ):

                    if (
                        self.flows[index]["timestamp"]
                        <= flow["timestamp"]
                    ):
                        insert_at = index + 1
                        break

                self.flows.insert(
                    insert_at,
                    flow,
                )

            self.received_flows += 1

            cutoff = (
                self.latest_timestamp
                - pd.Timedelta(
                    seconds=max(WINDOWS)
                )
            )

            while (
                self.flows
                and self.flows[0]["timestamp"]
                < cutoff
            ):
                self.flows.popleft()

            if (
                len(self.flows) < 15
                or self.received_flows
                % self.evaluation_every_flows
            ):
                return []

            features = multiscale_features(
                self.flows,
                self.latest_timestamp,
            )

            assessment = self.model.assess(
                features
            )

            if not assessment["is_alert"]:
                return []

            evidence = self._evidence(
                features
            )

            action = (
                self.correlator.decide(
                    assessment,
                    evidence,
                    flow,
                    self.latest_timestamp,
                )
            )

            if action is None:
                return []

            alert_context = {
                "trigger_flow": flow.get(
                    "context",
                    {},
                ),
                "window": context_summary(
                    pd.DataFrame(list(self.flows))
                ),
            }
            alert_id = hashlib.sha256(
                (
                    f"{self.latest_timestamp.isoformat()}|"
                    f"{flow['src_ip']}|{flow['src_port']}|"
                    f"{flow['dst_ip']}|{flow['dst_port']}|"
                    f"{assessment['threat_class']}"
                ).encode()
            ).hexdigest()[:16]

            alert = {
                "alert_id": alert_id,
                "timestamp": (
                    self.latest_timestamp
                    .isoformat()
                ),
                "event": action,
                "threat_class": (
                    assessment["threat_class"]
                ),
                "risk_score": round(
                    assessment["risk"],
                    3,
                ),
                "classification_confidence": round(
                    assessment[
                        "classification_confidence"
                    ],
                    3,
                ),
                "anomaly_confidence": round(
                    assessment[
                        "anomaly_confidence"
                    ],
                    3,
                ),
                "flow_identifier": (
                    f"{flow['src_ip']}:"
                    f"{flow['src_port']}->"
                    f"{flow['dst_ip']}:"
                    f"{flow['dst_port']}"
                ),
                "context": alert_context,
                "metadata_identification": identify_context(
                    alert_context["trigger_flow"]
                ),
                "detection_basis": {
                    "behavioral_ml": {
                        "classification_confidence": round(
                            assessment[
                                "classification_confidence"
                            ],
                            3,
                        ),
                        "anomaly_confidence": round(
                            assessment[
                                "anomaly_confidence"
                            ],
                            3,
                        ),
                        "temporal_confidence": round(
                            assessment[
                                "temporal_confidence"
                            ],
                            3,
                        ),
                    },
                    "contextual_metadata": identify_context(
                        alert_context["trigger_flow"]
                    ),
                },
                "supporting_evidence": evidence,
            }

            self.alerts.append(alert)

            return [alert]

    @staticmethod
    def _evidence(
        features: dict[str, float],
    ) -> dict[str, Any]:

        keys = (
            "w60_flow_count",
            "w60_flows_per_second",
            "w60_source_entropy",
            "w60_syn_ratio",
            "w60_port_fanout_per_source",
            "w300_periodicity",
            "w1800_host_fanout_per_source",
            "burst_ratio_60_300",
            "persistence_ratio_300_1800",
            "periodicity_consensus",
        )

        return {
            key: round(
                float(
                    features.get(
                        key,
                        0.0,
                    )
                ),
                3,
            )
            for key in keys
        }


# ---------------------------------------------------------------------------
# Synthetic traffic generators
# ---------------------------------------------------------------------------

def _sample_context(
    asset_id: str,
    hostname: str,
    role: str,
    services: list[str],
    baseline: str,
    destination_category: str,
    destination_score: int,
    dns_query: str,
    auth_result: str,
    available_fields: Iterable[str] | None = None,
) -> dict[str, Any]:
    context = {
        "asset_identity": {
            "asset_id": asset_id,
            "hostname": hostname,
            "network_zone": "demo-lab",
        },
        "known_services": services,
        "user_device_role": role,
        "historical_behavior": {
            "baseline": baseline,
            "observation_window": "30d",
        },
        "destination_reputation": {
            "category": destination_category,
            "score": destination_score,
            "source": "hackathon-demo-feed",
        },
        "dns_metadata": {
            "query": dns_query,
            "record_type": "A",
            "resolver": "10.0.0.53",
        },
        "authentication_events": [
            {
                "result": auth_result,
                "method": "password",
                "recent_failures": 0
                if auth_result == "success"
                else 4,
            }
        ],
    }

    if available_fields is None:
        return context

    allowed = set(available_fields)
    return {
        field: value
        for field, value in context.items()
        if field in allowed
    }

def generate_benign_flows(
    n: int = 1500,
    duration: int = 120,
) -> list[list[Any]]:

    flows = []
    start = datetime.now()

    for _ in range(n):

        ts = start + timedelta(
            seconds=random.uniform(
                0,
                duration,
            )
        )

        src = (
            f"192.168.1."
            f"{random.randint(1, 50)}"
        )

        dst = (
            f"10.0."
            f"{random.randint(0, 3)}."
            f"{random.randint(1, 254)}"
        )

        protocol = random.choices(
            ["TCP", "UDP"],
            weights=[0.9, 0.1],
        )[0]

        out = int(
            np.random.exponential(5000)
        )

        incoming = int(
            np.random.exponential(10000)
        )

        flows.append(
            [
                ts,
                src,
                dst,
                random.randint(1024, 65535),
                random.choice(
                    [
                        80,
                        443,
                        53,
                        8080,
                        22,
                        25,
                    ]
                ),
                protocol,
                out,
                incoming,
                max(
                    1,
                    out
                    // random.randint(
                        50,
                        500,
                    ),
                ),
                max(
                    1,
                    incoming
                    // random.randint(
                        50,
                        500,
                    ),
                ),
                "..."
                if protocol == "TCP"
                else "",
                "",
                "",
                _sample_context(
                    f"asset-{src.split('.')[-1]}",
                    f"workstation-{src.split('.')[-1]}",
                    "employee-workstation",
                    ["web", "dns"]
                    if protocol == "TCP"
                    else ["dns"],
                    "normal",
                    "trusted",
                    92,
                    "updates.example.internal",
                    "success",
                    (
                        "asset_identity",
                        "known_services",
                        "user_device_role",
                        "historical_behavior",
                        "destination_reputation",
                        "dns_metadata",
                    )
                    if random.random() < 0.65
                    else None,
                ),
            ]
        )

    return flows


def generate_ddos_flows(
    n: int = 800,
    duration: int = 30,
) -> list[list[Any]]:

    flows = []
    start = datetime.now()
    victim = "10.0.0.100"

    for _ in range(n):

        flows.append(
            [
                start
                + timedelta(
                    seconds=random.uniform(
                        0,
                        duration,
                    )
                ),
                f"203.0.113."
                f"{random.randint(1, 254)}",
                victim,
                random.randint(
                    1024,
                    65535,
                ),
                80,
                "TCP",
                0,
                0,
                1,
                0,
                "S",
                "",
                "",
                _sample_context(
                    "asset-ddos-victim",
                    "api-gateway-01",
                    "internet-facing-service",
                    ["https", "api"],
                    "normal",
                    "trusted",
                    90,
                    "api.example.internal",
                    "success",
                    (
                        "asset_identity",
                        "known_services",
                        "user_device_role",
                        "historical_behavior",
                        "destination_reputation",
                    ),
                ),
            ]
        )

    for _ in range(int(n * 0.3)):

        out = random.randint(
            1000,
            5000,
        )

        flows.append(
            [
                start
                + timedelta(
                    seconds=random.uniform(
                        0,
                        duration,
                    )
                ),
                f"198.51.100."
                f"{random.randint(1, 254)}",
                victim,
                53,
                random.randint(
                    1024,
                    65535,
                ),
                "UDP",
                out,
                100,
                random.randint(1, 5),
                1,
                "",
                "",
                "",
                _sample_context(
                    "asset-ddos-reflector",
                    "unknown-source",
                    "unmanaged-external-host",
                    ["dns"],
                    "unusual",
                    "suspicious",
                    38,
                    "resolver.example.net",
                    "failure",
                    (
                        "destination_reputation",
                        "dns_metadata",
                        "authentication_events",
                    ),
                ),
            ]
        )

    return flows


def generate_beaconing_flows(
    n_bots: int = 10,
    beacons_per_bot: int = 20,
    interval: int = 30,
    duration: int = 600,
) -> list[list[Any]]:

    del duration

    flows = []
    start = datetime.now()

    c2_ips = [
        f"185.220.101.{i}"
        for i in range(1, 5)
    ]

    for bot_id in range(n_bots):

        src = (
            f"192.168.1."
            f"{50 + bot_id}"
        )

        c2 = random.choice(c2_ips)

        for i in range(
            beacons_per_bot
        ):

            flows.append(
                [
                    start
                    + timedelta(
                        seconds=(
                            i * interval
                            + random.uniform(
                                -2,
                                2,
                            )
                        )
                    ),
                    src,
                    c2,
                    random.randint(
                        1024,
                        65535,
                    ),
                    443,
                    "TCP",
                    random.randint(
                        50,
                        200,
                    ),
                    random.randint(
                        100,
                        300,
                    ),
                    1,
                    1,
                    "...",
                    "",
                    "malicious_c2_fingerprint",
                    _sample_context(
                        f"asset-bot-{bot_id + 1}",
                        f"engineering-laptop-{bot_id + 1}",
                        "employee-workstation",
                        ["https", "dns"],
                        "unusual",
                        "malicious",
                        4,
                        f"update-cdn-{bot_id + 1}.example.net",
                        "success",
                        (
                            "asset_identity",
                            "known_services",
                            "user_device_role",
                            "historical_behavior",
                            "destination_reputation",
                            "dns_metadata",
                        )
                        if i % 3
                        else (
                            "asset_identity",
                            "destination_reputation",
                            "dns_metadata",
                        ),
                    ),
                ]
            )

    return flows


def generate_port_scan_flows(
    n_scans: int = 5,
    ports_per_scan: int = 200,
    duration: int = 60,
) -> list[list[Any]]:

    flows = []
    start = datetime.now()

    for _ in range(n_scans):

        target = random.choice(
            [
                "10.0.0.5",
                "10.0.0.6",
                "10.0.1.10",
            ]
        )

        for port in random.sample(
            range(1, 65535),
            ports_per_scan,
        ):

            flows.append(
                [
                    start
                    + timedelta(
                        seconds=random.uniform(
                            0,
                            duration,
                        )
                    ),
                    "192.168.1.70",
                    target,
                    random.randint(
                        1024,
                        65535,
                    ),
                    port,
                    "TCP",
                    0,
                    0,
                    1,
                    0,
                    "S",
                    "",
                    "",
                    _sample_context(
                        "asset-scan-source",
                        "admin-workstation-07",
                        "administrator-workstation",
                        ["ssh", "https"],
                        "unusual",
                        "trusted",
                        86,
                        f"host-{target.replace('.', '-')}.internal",
                        "failure",
                        (
                            "asset_identity",
                            "known_services",
                            "user_device_role",
                            "historical_behavior",
                            "destination_reputation",
                        )
                        if port % 2
                        else (
                            "asset_identity",
                            "known_services",
                            "destination_reputation",
                            "authentication_events",
                        ),
                    ),
                ]
            )

    return flows


def _as_dicts(
    rows: list[list[Any]],
) -> list[dict[str, Any]]:

    names = (
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "bytes_out",
        "bytes_in",
        "packets_out",
        "packets_in",
        "tcp_flags",
        "dns_query",
        "tls_fingerprint",
        "context",
    )

    return [
        dict(zip(names, row))
        for row in rows
    ]


def samples_for_scenario(
    rows: list[list[Any]],
    label: str,
    samples_per_scenario: int = 8,
) -> tuple[list[dict[str, float]], list[str]]:

    flows = sorted(
        (
            validate_flow(row)
            for row in _as_dicts(rows)
        ),
        key=lambda row: row["timestamp"],
    )

    buffer: deque[
        dict[str, Any]
    ] = deque()

    samples: list[
        dict[str, float]
    ] = []

    sample_points = set(
        np.linspace(
            19,
            len(flows) - 1,
            min(
                samples_per_scenario,
                max(
                    0,
                    len(flows) - 19,
                ),
            ),
            dtype=int,
        )
    )

    for index, flow in enumerate(flows):

        buffer.append(flow)

        cutoff = (
            flow["timestamp"]
            - pd.Timedelta(
                seconds=max(WINDOWS)
            )
        )

        while (
            buffer
            and buffer[0]["timestamp"]
            < cutoff
        ):
            buffer.popleft()

        if (
            len(buffer) >= 20
            and index in sample_points
        ):

            samples.append(
                multiscale_features(
                    buffer,
                    flow["timestamp"],
                )
            )

    return samples, [
        label
        for _ in samples
    ]


def build_training_set(
    runs_per_class: int = 10,
) -> tuple[pd.DataFrame, list[str]]:

    generators = {
        "Benign": lambda:
            generate_benign_flows(
                700,
                120,
            ),

        "DDoS": lambda:
            generate_ddos_flows(
                random.randint(
                    300,
                    550,
                ),
                random.randint(
                    15,
                    30,
                ),
            ),

        "Botnet C2 Beaconing": lambda:
            generate_beaconing_flows(
                random.randint(5, 10),
                random.randint(12, 22),
                10,
                600,
            ),

        "Port Scanning": lambda:
            generate_port_scan_flows(
                random.randint(2, 5),
                random.randint(120, 220),
                60,
            ),
    }

    windows: list[
        dict[str, float]
    ] = []

    labels: list[str] = []

    for label, generator in generators.items():

        for _ in range(
            runs_per_class
        ):

            sample, sample_labels = (
                samples_for_scenario(
                    generator(),
                    label,
                )
            )

            windows.extend(sample)
            labels.extend(sample_labels)

    X = (
        pd.DataFrame(windows)
        .replace(
            [np.inf, -np.inf],
            0.0,
        )
        .fillna(0.0)
    )

    rng = np.random.default_rng(42)

    kept: list[int] = []

    counts = Counter(labels)

    limit = min(
        counts.values()
    )

    for label in LABELS:

        indexes = np.flatnonzero(
            np.asarray(labels) == label
        )

        kept.extend(
            rng.choice(
                indexes,
                size=limit,
                replace=False,
            ).tolist()
        )

    kept.sort()

    return (
        X.iloc[kept]
        .reset_index(drop=True),
        [
            labels[index]
            for index in kept
        ],
    )


def train_model(
    runs_per_class: int = 10,
) -> ArgusFusionModel:

    X, y = build_training_set(
        runs_per_class
    )

    classifier = (
        RobustPrototypeModel()
        .fit(X, y)
    )

    benign = (
        X.loc[
            np.asarray(y)
            == "Benign"
        ]
        .reset_index(drop=True)
    )

    guard = (
        BenignAnomalyGuard()
        .fit(benign)
    )

    print(
        f"trained {len(X)} balanced "
        f"scenario windows: "
        f"{dict(Counter(y))}"
    )

    return ArgusFusionModel(
        classifier,
        guard,
    )


def run_demo(
    model: ArgusFusionModel,
    scenario: str,
    stop_event: threading.Event | None = None,
) -> list[dict[str, Any]]:

    generators = {
        "ddos": generate_ddos_flows,
        "beaconing": generate_beaconing_flows,
        "portscan": generate_port_scan_flows,
    }

    if scenario not in generators:
        raise ValueError(
            "scenario must be one of "
            f"{sorted(generators)}"
        )

    detector = ArgusOneDetector(model)

    alerts: list[
        dict[str, Any]
    ] = []

    flows = sorted(
        _as_dicts(
            generators[scenario]()
        ),
        key=lambda row: row["timestamp"],
    )

    for flow in flows:

        # Stop request is checked before every
        # flow so the simulation terminates
        # without processing unnecessary records.
        if (
            stop_event
            and stop_event.is_set()
        ):
            break

        alerts.extend(
            detector.process_flow(flow)
        )

    return alerts


# ---------------------------------------------------------------------------
# Interactive dashboard
# ---------------------------------------------------------------------------

LANDING_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>ARGUS-ONE | Passive Threat Detection</title>

<style>
:root {
    color-scheme: dark;
    --ink:#e9f2ff;
    --muted:#8ea4c4;
    --line:#253653;
    --panel:#0f1b31;
    --blue:#4ea1ff;
    --cyan:#51e2c2;
    --red:#ff6e87;
    --amber:#ffbf5b;
}

* {
    box-sizing:border-box;
}

body {
    margin:0;
    min-height:100vh;
    color:var(--ink);
    font:16px/1.5 Inter,Segoe UI,Arial,sans-serif;
    background:
        radial-gradient(
            circle at 18% 18%,
            #193c69 0,
            transparent 32%
        ),
        linear-gradient(
            135deg,
            #07101f,
            #0c1628 55%,
            #10172d
        );
}

button {
    font:inherit;
    cursor:pointer;
}

.shell {
    width:min(
        1120px,
        calc(100% - 40px)
    );
    margin:auto;
    padding:28px 0 56px;
}

nav {
    display:flex;
    justify-content:space-between;
    align-items:center;
    color:var(--muted);
}

.brand {
    color:var(--ink);
    font-weight:800;
    letter-spacing:.12em;
}

.mark {
    display:inline-grid;
    place-items:center;
    width:28px;
    height:28px;
    margin-right:8px;
    border:1px solid var(--cyan);
    border-radius:50%;
    color:var(--cyan);
}

.tag {
    padding:5px 10px;
    border:1px solid #27466c;
    border-radius:999px;
    font-size:12px;
    color:var(--cyan);
}

.page {
    display:none;
}

.page.active {
    display:block;
}

.hero {
    min-height:72vh;
    display:grid;
    align-content:center;
    grid-template-columns:1.2fr .8fr;
    gap:56px;
}

.eyebrow {
    color:var(--cyan);
    font-size:13px;
    font-weight:700;
    letter-spacing:.14em;
    text-transform:uppercase;
}

.hero h1 {
    margin:12px 0 18px;
    font-size:clamp(
        42px,
        7vw,
        80px
    );
    line-height:.96;
    letter-spacing:-.055em;
}

.hero p {
    max-width:620px;
    color:var(--muted);
    font-size:19px;
}

.primary {
    border:0;
    border-radius:10px;
    padding:14px 21px;
    background:var(--blue);
    color:#031327;
    font-weight:800;
    box-shadow:
        0 10px 30px #2866b05e;
}

.primary:hover {
    transform:translateY(-1px);
    filter:brightness(1.1);
}

.radar {
    align-self:center;
    aspect-ratio:1;
    display:grid;
    place-items:center;
    border:1px solid #34507b;
    border-radius:50%;
    background:
        repeating-radial-gradient(
            circle,
            #0e213b 0 13%,
            #21446d 13.5% 14%,
            #0e213b 14.5% 27%
        );
    box-shadow:
        inset 0 0 80px #12375d,
        0 0 60px #1a58a244;
}

.radar span {
    color:var(--cyan);
    font-size:42px;
    animation:pulse 2s infinite;
}

@keyframes pulse {
    50% {
        opacity:.35;
        transform:scale(1.2);
    }
}

.facts {
    display:flex;
    gap:18px;
    flex-wrap:wrap;
    color:var(--muted);
    font-size:14px;
}

.facts span {
    border-left:2px solid var(--cyan);
    padding-left:10px;
}

.console-head {
    margin:56px 0 24px;
    display:flex;
    justify-content:space-between;
    align-items:end;
    gap:20px;
}

.console-head h2 {
    margin:0;
    font-size:34px;
}

.console-head p {
    margin:4px 0;
    color:var(--muted);
}

.back {
    border:1px solid var(--line);
    border-radius:8px;
    background:transparent;
    color:var(--ink);
    padding:9px 12px;
}

.cards {
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:16px;
}

.card,
.results {
    background:
        linear-gradient(
            145deg,
            #11203a,
            #0e182b
        );
    border:1px solid var(--line);
    border-radius:14px;
    padding:21px;
}

.card {
    min-height:238px;
    display:flex;
    flex-direction:column;
}

.card .icon {
    font-size:28px;
}

.card h3 {
    margin:12px 0 6px;
}

.card p {
    margin:0;
    color:var(--muted);
    font-size:14px;
}

.run {
    margin-top:auto;
    border:1px solid #305587;
    border-radius:8px;
    background:#122845;
    color:var(--ink);
    padding:10px;
    font-weight:700;
}

.run:hover {
    border-color:var(--blue);
    background:#183764;
}

.run:disabled {
    opacity:.5;
    cursor:not-allowed;
}

.results {
    margin-top:20px;
}

.status-row {
    display:flex;
    justify-content:space-between;
    gap:20px;
    align-items:center;
    padding-bottom:16px;
    border-bottom:1px solid var(--line);
}

.status {
    color:var(--amber);
    font-weight:700;
}

.actions {
    display:flex;
    gap:8px;
    flex-wrap:wrap;
    margin-left:auto;
}

.secondary {
    border:1px solid var(--line);
    border-radius:8px;
    background:transparent;
    color:var(--ink);
    padding:8px 10px;
    font-size:13px;
}

.secondary:hover {
    border-color:var(--blue);
    background:#142a47;
}

.danger {
    border-color:#6d3142;
    color:#ff9cac;
}

.danger:hover {
    background:#40202c;
    border-color:var(--red);
}

.secondary:disabled {
    opacity:.42;
    cursor:not-allowed;
}

.metrics {
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:12px;
    margin:16px 0;
}

.metric {
    padding:13px;
    border-radius:9px;
    background:#0a1425;
}

.metric b {
    display:block;
    font-size:23px;
    color:var(--cyan);
}

.metric small {
    color:var(--muted);
}

table {
    width:100%;
    border-collapse:collapse;
    font-size:13px;
}

th,
td {
    text-align:left;
    padding:10px 6px;
    border-bottom:1px solid #1d2c45;
}

th {
    color:var(--muted);
    font-weight:600;
}

.empty {
    color:var(--muted);
    padding:25px 0;
}

.pill {
    padding:3px 7px;
    border-radius:999px;
    background:#18345d;
    color:#9ecbff;
    font-size:12px;
    white-space:nowrap;
}

@media(max-width:760px) {

    .hero {
        grid-template-columns:1fr;
        gap:15px;
    }

    .radar {
        width:180px;
    }

    .cards {
        grid-template-columns:1fr;
    }

    .metrics {
        grid-template-columns:1fr;
    }

    .console-head {
        align-items:start;
        flex-direction:column;
    }

    .shell {
        width:min(
            100% - 28px,
            1120px
        );
    }

    .status-row {
        align-items:flex-start;
        flex-direction:column;
    }

    .actions {
        margin-left:0;
    }
}
</style>
</head>

<body>

<main class="shell">

<nav>
    <div class="brand">
        <span class="mark">A</span>
        ARGUS-ONE
    </div>

    <div class="tag">
        PASSIVE / ONE-WAY
    </div>
</nav>

<section id="landing" class="page active">

    <div class="hero">

        <div>

            <div class="eyebrow">
                Threat intelligence for isolated networks
            </div>

            <h1>
                See risk.<br>
                Keep isolation.
            </h1>

            <p>
                ARGUS-ONE detects anomalous behavior
                from passively collected network-flow
                metadata—without opening a return path
                or decrypting traffic.
            </p>

            <button
                id="enter"
                class="primary"
            >
                Open detection console →
            </button>

            <div
                class="facts"
                style="margin-top:34px"
            >
                <span>
                    Multi-horizon analytics
                </span>

                <span>
                    Metadata only
                </span>

                <span>
                    Evidence-led alerts
                </span>
            </div>

        </div>

        <div
            class="radar"
            aria-hidden="true"
        >
            <span>◉</span>
        </div>

    </div>

</section>

<section id="console" class="page">

    <div class="console-head">

        <div>

            <div class="eyebrow">
                Simulation workspace
            </div>

            <h2>
                Select a threat scenario
            </h2>

            <p>
                Run a passive-flow replay
                to inspect the hybrid
                detector’s alert decisions.
            </p>

        </div>

        <button
            id="back"
            class="back"
        >
            ← Startup page
        </button>

    </div>

    <div class="cards">

        <article class="card">

            <div class="icon">
                ◌
            </div>

            <h3>
                DDoS flood
            </h3>

            <p>
                Spoofed-source SYN flood
                plus UDP-reflection behaviour
                against a protected destination.
            </p>

            <button
                class="run"
                data-scenario="ddos"
            >
                Run DDoS simulation
            </button>

        </article>

        <article class="card">

            <div class="icon">
                ⌁
            </div>

            <h3>
                Botnet C2 beaconing
            </h3>

            <p>
                Small, periodic outbound flows
                from internal hosts to external
                command-and-control endpoints.
            </p>

            <button
                class="run"
                data-scenario="beaconing"
            >
                Run beaconing simulation
            </button>

        </article>

        <article class="card">

            <div class="icon">
                ⌘
            </div>

            <h3>
                Port scan
            </h3>

            <p>
                A single source probing large
                port ranges across protected hosts.
            </p>

            <button
                class="run"
                data-scenario="portscan"
            >
                Run port-scan simulation
            </button>

        </article>

    </div>

    <section class="results">

        <div class="status-row">

            <div>
                <b>
                    Simulation status
                </b>

                <div
                    id="status"
                    class="status"
                >
                    Ready — select a scenario.
                </div>
            </div>

            <div class="actions">

                <!-- STOP BUTTON -->
                <button
                    id="stop"
                    class="secondary danger"
                    disabled
                >
                    Stop simulation
                </button>

                <!-- CLEAR ALERTS BUTTON -->
                <button
                    id="clear"
                    class="secondary"
                    disabled
                >
                    Clear alerts
                </button>

                <span
                    id="scenario"
                    class="pill"
                >
                    IDLE
                </span>

            </div>

        </div>

        <div class="metrics">

            <div class="metric">
                <b id="alertCount">0</b>
                <small>Alerts emitted</small>
            </div>

            <div class="metric">
                <b id="classCount">—</b>
                <small>Detected class</small>
            </div>

            <div class="metric">
                <b id="risk">—</b>
                <small>Latest risk score</small>
            </div>

        </div>

        <div
            id="empty"
            class="empty"
        >
            No completed simulation yet.
        </div>

        <table
            id="alertTable"
            hidden
        >

            <thead>

                <tr>
                    <th>Event</th>
                    <th>Class</th>
                    <th>Risk</th>
                    <th>Flow</th>
                    <th>Metadata</th>
                    <th>Feedback</th>
                </tr>

            </thead>

            <tbody id="alerts"></tbody>

        </table>

    </section>

</section>

</main>

<script>

const landing =
    document.querySelector('#landing');

const consolePage =
    document.querySelector('#console');

const buttons =
    [...document.querySelectorAll('.run')];

document.querySelector('#enter').onclick = () => {

    landing.classList.remove('active');
    consolePage.classList.add('active');

};

document.querySelector('#back').onclick = () => {

    consolePage.classList.remove('active');
    landing.classList.add('active');

};


const esc = value =>
    String(value ?? '')
        .replace(
            /[&<>"']/g,
            char => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            }[char])
        );


function render(state) {

    const status =
        document.querySelector('#status');

    const label =
        document.querySelector('#scenario');

    const stop =
        document.querySelector('#stop');

    const clear =
        document.querySelector('#clear');

    status.textContent =
        state.message || state.status;

    label.textContent =
        (state.scenario || 'idle').toUpperCase();


    /*
     * Both "running" and "stopping" are
     * considered active states.
     */
    const active =
        state.status === 'running' ||
        state.status === 'stopping';

    const modelLoading =
        state.status === 'model_loading';


    /*
     * Prevent starting another scenario
     * while one is active.
     */
    buttons.forEach(button => {
        button.disabled = active || modelLoading;
    });


    /*
     * Stop is only available while running.
     * Once the user has clicked it, prevent
     * repeated stop requests.
     */
    stop.disabled =
        state.status !== 'running';


    /*
     * Clear is available only after the
     * simulation has stopped/completed and
     * there are alerts to clear.
     */
    clear.disabled =
        active ||
        modelLoading ||
        !(state.alert_count > 0);


    /*
     * While the replay is running/stopping,
     * keep the current result display.
     */
    if (modelLoading) {
        status.textContent = 'Loading detection model…';
        return;
    }

    if (active) {
        status.textContent =
            state.status === 'stopping'
                ? 'Stopping replay safely…'
                : 'Running '
                    + state.scenario
                    + ' replay…';

        return;
    }


    const alerts =
        state.alerts || [];

    const last =
        alerts.at(-1);


    document.querySelector(
        '#alertCount'
    ).textContent =
        state.alert_count || 0;


    document.querySelector(
        '#classCount'
    ).textContent =
        last?.threat_class || '—';


    document.querySelector(
        '#risk'
    ).textContent =
        last
            ? Number(
                last.risk_score
              ).toFixed(3)
            : '—';


    document.querySelector(
        '#empty'
    ).hidden =
        alerts.length > 0;


    document.querySelector(
        '#alertTable'
    ).hidden =
        alerts.length === 0;


    document.querySelector(
        '#alerts'
    ).innerHTML =
        alerts
            .slice()
            .reverse()
            .map(
                alert => `
                    <tr>
                        <td>
                            ${esc(alert.event)}
                        </td>

                        <td>
                            ${esc(
                                alert.threat_class
                            )}
                        </td>

                        <td>
                            ${esc(
                                Number(
                                    alert.risk_score
                                ).toFixed(3)
                            )}
                        </td>

                        <td>
                            ${esc(
                                alert.flow_identifier
                            )}
                        </td>

                        <td>
                            ${Math.round(
                                Number(
                                    alert.metadata_identification
                                        ?.coverage || 0
                                ) * 100
                            )}% available
                        </td>

                        <td>
                            <button
                                class="feedback"
                                onclick="submitFeedback('${esc(
                                    alert.alert_id
                                )}', 'false_positive')"
                            >
                                False positive
                            </button>

                            <button
                                class="feedback"
                                onclick="submitFeedback('${esc(
                                    alert.alert_id
                                )}', 'confirmed_threat')"
                            >
                                Confirm threat
                            </button>
                        </td>
                    </tr>
                `
            )
            .join('');
}


async function submitFeedback(alertId, verdict) {

    try {

        const response = await fetch(
            '/api/feedback',
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    alert_id: alertId,
                    verdict: verdict
                })
            }
        );

        if (!response.ok) {
            throw new Error('feedback rejected');
        }

        document.querySelector(
            '#status'
        ).textContent =
            verdict === 'false_positive'
                ? 'False positive recorded for tuning.'
                : 'Confirmed threat recorded for tuning.';

    } catch {

        document.querySelector(
            '#status'
        ).textContent =
            'Unable to record analyst feedback.';
    }
}


/*
 * Poll server state.
 */
async function refresh() {

    try {

        const response =
            await fetch('/api/status');

        const state =
            await response.json();

        render(state);

    } catch {

        document.querySelector(
            '#status'
        ).textContent =
            'Connection to local detector lost.';
    }
}


/*
 * Start simulation.
 */
buttons.forEach(button => {

    button.onclick = async () => {

        try {

            const response =
                await fetch(
                    '/api/simulate/'
                    + button.dataset.scenario,
                    {
                        method: 'POST'
                    }
                );

            const state =
                await response.json();

            render(state);

        } catch {

            document.querySelector(
                '#status'
            ).textContent =
                'Unable to start simulation.';
        }

    };

});


/*
 * STOP SIMULATION
 */
document.querySelector(
    '#stop'
).onclick = async () => {

    try {

        const response =
            await fetch(
                '/api/stop',
                {
                    method: 'POST'
                }
            );

        const state =
            await response.json();

        render(state);

    } catch {

        document.querySelector(
            '#status'
        ).textContent =
            'Unable to stop the simulation.';
    }

};


/*
 * CLEAR ALERTS
 */
document.querySelector(
    '#clear'
).onclick = async () => {

    try {

        const response =
            await fetch(
                '/api/clear',
                {
                    method: 'POST'
                }
            );

        const state =
            await response.json();

        render(state);

    } catch {

        document.querySelector(
            '#status'
        ).textContent =
            'Unable to clear alerts.';
    }

};


/*
 * Refresh state every 1.2 seconds.
 */
setInterval(
    refresh,
    1200
);

refresh();

</script>

</body>
</html>'''


class SimulationService:
    """Owns one local simulation at a time and exposes safe dashboard state."""

    def __init__(self, model: ArgusFusionModel | None = None) -> None:
        self.model = model
        self.lock = threading.RLock()
        self.state: dict[str, Any] = {
            "status": "ready" if model is not None else "model_loading",
            "scenario": None,
            "message": (
                "Ready — select a scenario."
                if model is not None
                else "Loading detection model…"
            ),
            "alerts": [],
            "alert_count": 0,
        }
        self.stop_event: threading.Event | None = None
        self.worker: threading.Thread | None = None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.state)

    def set_model(self, model: ArgusFusionModel) -> None:
        with self.lock:
            self.model = model
            if self.state["status"] == "model_loading":
                self.state = {
                    "status": "ready",
                    "scenario": None,
                    "message": "Ready — select a scenario.",
                    "alerts": [],
                    "alert_count": 0,
                }

    def set_model_error(self, error: Exception) -> None:
        with self.lock:
            self.model = None
            self.state = {
                "status": "error",
                "scenario": None,
                "message": f"Model startup failed: {error}",
                "alerts": [],
                "alert_count": 0,
            }

    def start(self, scenario: str) -> tuple[bool, dict[str, Any]]:
        if scenario not in {"ddos", "beaconing", "portscan"}:
            return False, {
                "status": "error",
                "message": "Unknown simulation scenario.",
                "alerts": [],
                "alert_count": 0,
            }

        with self.lock:
            if self.model is None:
                return False, {
                    **dict(self.state),
                    "status": self.state.get("status", "model_loading"),
                    "message": "Detection model is still loading. Please try again in a moment.",
                }

            if self.state["status"] in {"running", "stopping"}:
                return False, dict(self.state)

            self.stop_event = threading.Event()
            self.state = {
                "status": "running",
                "scenario": scenario,
                "message": "Preparing passive-flow replay…",
                "alerts": [],
                "alert_count": 0,
            }

            self.worker = threading.Thread(
                target=self._run,
                args=(scenario, self.stop_event),
                daemon=True,
                name=f"ARGUS-ONE-{scenario}",
            )
            self.worker.start()

        return True, self.snapshot()

    def stop(self) -> dict[str, Any]:
        with self.lock:
            if (
                self.state["status"] != "running"
                or self.stop_event is None
            ):
                return {
                    "status": "error",
                    "scenario": self.state.get("scenario"),
                    "message": "No simulation is running.",
                    "alerts": self.state.get("alerts", []),
                    "alert_count": self.state.get("alert_count", 0),
                }

            self.stop_event.set()
            self.state["status"] = "stopping"
            self.state["message"] = "Stopping replay safely…"
            return dict(self.state)

    def clear(self) -> tuple[bool, dict[str, Any]]:
        with self.lock:
            if self.state["status"] in {"running", "stopping"}:
                return False, {
                    "status": "error",
                    "scenario": self.state.get("scenario"),
                    "message": (
                        "Stop the active simulation before clearing alerts."
                    ),
                    "alerts": self.state.get("alerts", []),
                    "alert_count": self.state.get("alert_count", 0),
                }

            # Preserve the loaded model; only clear the displayed alerts.
            self.state["status"] = "ready" if self.model is not None else "model_loading"
            self.state["message"] = "Alerts cleared."
            self.state["alerts"] = []
            self.state["alert_count"] = 0
            return True, dict(self.state)

    def _run(
        self,
        scenario: str,
        stop_event: threading.Event,
    ) -> None:
        try:
            model = self.model
            if model is None:
                raise RuntimeError("Detection model is not loaded.")

            alerts = run_demo(
                model,
                scenario,
                stop_event,
            )

            with self.lock:
                stopped = stop_event.is_set()
                self.state = {
                    "status": "stopped" if stopped else "complete",
                    "scenario": scenario,
                    "message": (
                        f"Stopped {scenario} replay."
                        if stopped
                        else f"Completed {scenario} replay."
                    ),
                    "alerts": alerts[-50:],
                    "alert_count": len(alerts),
                }

        except Exception as error:
            with self.lock:
                self.state = {
                    "status": "error",
                    "scenario": scenario,
                    "message": f"Simulation failed: {error}",
                    "alerts": [],
                    "alert_count": 0,
                }

        finally:
            with self.lock:
                self.worker = None
                self.stop_event = None

class FeedbackStore:
    """Append-only analyst feedback for future tuning and review."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()

    def record(
        self,
        alert_id: str,
        verdict: str,
        note: str = "",
    ) -> dict[str, Any]:
        if verdict not in {
            "false_positive",
            "confirmed_threat",
            "false_negative",
        }:
            raise ValueError("unsupported feedback verdict")

        entry = {
            "timestamp": datetime.now().astimezone().isoformat(),
            "alert_id": str(alert_id)[:64],
            "verdict": verdict,
            "note": str(note)[:CONTEXT_VALUE_LIMIT],
        }

        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")

        return entry


def serve_dashboard(
    model: ArgusFusionModel | None,
    host: str,
    port: int,
    model_loader: Any | None = None,
    feedback_path: Path = Path("argus_one_feedback.jsonl"),
) -> None:
    service = SimulationService(model)
    feedback = FeedbackStore(feedback_path)

    if model is None and model_loader is not None:
        def load_model_in_background() -> None:
            try:
                loaded_model = model_loader()
                service.set_model(loaded_model)
                print("ARGUS-ONE detection model is ready.")
            except Exception as error:
                service.set_model_error(error)
                print(f"ARGUS-ONE model startup failed: {error}")

        threading.Thread(
            target=load_model_in_background,
            daemon=True,
            name="ARGUS-ONE-model-loader",
        ).start()

    class DashboardHandler(BaseHTTPRequestHandler):
        def _json(
            self,
            payload: dict[str, Any],
            status: HTTPStatus = HTTPStatus.OK,
        ) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header(
                "Content-Type",
                "application/json; charset=utf-8",
            )
            self.send_header(
                "Cache-Control",
                "no-store",
            )
            self.send_header(
                "Content-Length",
                str(len(body)),
            )
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path

            if path == "/":
                body = LANDING_HTML.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header(
                    "Content-Type",
                    "text/html; charset=utf-8",
                )
                self.send_header(
                    "Cache-Control",
                    "no-store",
                )
                self.send_header(
                    "Content-Length",
                    str(len(body)),
                )
                self.end_headers()
                self.wfile.write(body)

            elif path == "/api/status":
                self._json(service.snapshot())

            else:
                self._json(
                    {
                        "status": "error",
                        "message": "Not found.",
                    },
                    HTTPStatus.NOT_FOUND,
                )

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            parts = path.split("/")

            if path == "/api/feedback":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    payload = json.loads(
                        self.rfile.read(length) or b"{}"
                    )
                    entry = feedback.record(
                        payload["alert_id"],
                        payload["verdict"],
                        payload.get("note", ""),
                    )
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                    self._json(
                        {
                            "status": "error",
                            "message": f"Invalid feedback: {error}",
                        },
                        HTTPStatus.BAD_REQUEST,
                    )
                    return

                self._json(
                    {
                        "status": "ok",
                        "feedback": entry,
                    }
                )
                return

            if (
                len(parts) == 4
                and parts[:3] == ["", "api", "simulate"]
            ):
                started, response = service.start(parts[3])
                self._json(
                    response,
                    HTTPStatus.ACCEPTED
                    if started
                    else HTTPStatus.CONFLICT,
                )

            elif path == "/api/stop":
                response = service.stop()
                self._json(
                    response,
                    HTTPStatus.ACCEPTED
                    if response.get("status")
                    in {"running", "stopping"}
                    else HTTPStatus.CONFLICT,
                )

            elif path == "/api/clear":
                cleared, response = service.clear()
                self._json(
                    response,
                    HTTPStatus.OK
                    if cleared
                    else HTTPStatus.CONFLICT,
                )

            else:
                self._json(
                    {
                        "status": "error",
                        "message": "Not found.",
                    },
                    HTTPStatus.NOT_FOUND,
                )

        def log_message(
            self,
            format: str,
            *args: Any,
        ) -> None:
            return

    try:
        server = ThreadingHTTPServer(
            (host, port),
            DashboardHandler,
        )
    except OSError as error:
        raise RuntimeError(
            f"Could not bind dashboard to {host}:{port}: {error}"
        ) from error

    print(f"ARGUS-ONE dashboard: http://{host}:{port}")
    print("Press Ctrl+C to stop the local server.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train or smoke-test the ARGUS-ONE hybrid detector."
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("argus_one_hybrid_model.json"),
    )
    parser.add_argument(
        "--runs-per-class",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--demo",
        choices=("ddos", "beaconing", "portscan"),
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help=(
            "print replay counts and boundary alerts "
            "instead of the final five alerts"
        ),
    )
    parser.add_argument(
        "--retrain",
        action="store_true",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="serve the local interactive dashboard",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="dashboard bind host (default: local machine only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="dashboard port (default: 8080)",
    )
    args = parser.parse_args()

    # Web mode is intentionally non-blocking: the HTTP server starts
    # immediately. If a model already exists, load it before serving;
    # otherwise train it in the background while the dashboard shows
    # "Loading detection model…".
    if args.web:
        if args.model.exists() and not args.retrain:
            try:
                model = ArgusFusionModel.load(args.model)
            except Exception as error:
                print(f"Existing model could not be loaded: {error}")
                model = None
        else:
            model = None

        def model_loader() -> ArgusFusionModel:
            trained_model = train_model(args.runs_per_class)
            trained_model.save(args.model)
            print(f"saved model to {args.model}")
            return trained_model

        serve_dashboard(
            model,
            args.host,
            args.port,
            model_loader if model is None else None,
        )
        return

    if args.retrain or not args.model.exists():
        model = train_model(args.runs_per_class)
        model.save(args.model)
        print(f"saved model to {args.model}")
    else:
        model = ArgusFusionModel.load(args.model)

    if args.demo:
        alerts = run_demo(model, args.demo)

        if args.summary:
            print(
                json.dumps(
                    {
                        "scenario": args.demo,
                        "alerts": len(alerts),
                        "events": dict(
                            Counter(alert["event"] for alert in alerts)
                        ),
                        "classes": dict(
                            Counter(
                                alert["threat_class"]
                                for alert in alerts
                            )
                        ),
                        "first_alert": alerts[0] if alerts else None,
                        "last_alert": alerts[-1] if alerts else None,
                    },
                    indent=2,
                )
            )
        else:
            print(json.dumps(alerts[-5:], indent=2))


if __name__ == "__main__":
    main()