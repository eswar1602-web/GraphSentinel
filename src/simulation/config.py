"""Validated configuration of the live simulation (configs/simulation.yaml)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

DEFAULT_CONFIG = Path("configs/simulation.yaml")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClockConfig(_Strict):
    speed: float = Field(5.0, gt=0, le=100)
    tick_interval_s: float = Field(1.0, ge=0.02, le=10)
    duration_s: float | None = Field(None, gt=0, le=7 * 24 * 3600)


class NetworkConfig(_Strict):
    workstations: int = Field(12, ge=2, le=200)
    laptops: int = Field(6, ge=0, le=200)
    app_servers: int = Field(2, ge=1, le=20)
    db_servers: int = Field(1, ge=1, le=10)
    dns_servers: int = Field(1, ge=1, le=4)
    routers: int = Field(1, ge=1, le=4)
    external_endpoints: int = Field(8, ge=3, le=200)


class TrafficConfig(_Strict):
    normal_enabled: bool = True
    client_sessions_per_s: float = Field(0.12, ge=0, le=10)
    app_to_db_queries_per_s: float = Field(1.5, ge=0, le=100)
    dns_forward_per_s: float = Field(0.3, ge=0, le=100)
    router_ntp_per_s: float = Field(0.02, ge=0, le=10)
    admin_ssh_per_s: float = Field(0.01, ge=0, le=10)
    max_flows_per_tick: int = Field(5000, ge=10, le=50_000)


class DetectionConfig(_Strict):
    window_s: float = Field(60.0, gt=0, le=3600)
    baseline_warmup_s: float = Field(120.0, ge=0, le=86_400)
    alert_merge_s: float = Field(120.0, gt=0, le=86_400)
    port_scan_distinct_ports: int = Field(20, ge=2)
    host_sweep_distinct_hosts: int = Field(8, ge=2)
    conn_rate_per_s: float = Field(15.0, gt=0)
    volume_bytes: int = Field(20_000_000, gt=0)
    volume_upload_ratio: float = Field(5.0, gt=0)
    brute_force_attempts: int = Field(12, ge=2)
    brute_force_max_duration_s: float = Field(5.0, gt=0)
    auth_ports: list[int] = Field(default_factory=lambda: [21, 22, 23, 3389, 5900, 5985])
    admin_ports: list[int] = Field(default_factory=lambda: [22, 135, 139, 445, 3389, 5985, 5986])
    allowed_outbound_ports: list[int] = Field(default_factory=lambda: [53, 80, 123, 443])

    @field_validator("auth_ports", "admin_ports", "allowed_outbound_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 0 < p < 65536 for p in v):
            raise ValueError("ports must be in 1..65535")
        return sorted(set(v))


class MLConfig(_Strict):
    enabled: bool = True
    min_confidence: float = Field(0.9, ge=0.0, le=1.0)
    create_incidents: bool = False


class IncidentConfig(_Strict):
    correlation_window_s: float = Field(600.0, gt=0)
    min_severity_to_open: Literal["low", "medium", "high", "critical"] = "medium"


class LimitsConfig(_Strict):
    flow_buffer: int = Field(5000, ge=100, le=200_000)
    alert_buffer: int = Field(2000, ge=10, le=100_000)
    incident_buffer: int = Field(500, ge=10, le=100_000)
    evidence_flow_ids: int = Field(50, ge=1, le=1000)
    ws_queue: int = Field(500, ge=10, le=10_000)
    ws_flows_per_message: int = Field(200, ge=1, le=5000)


class SimConfig(_Strict):
    seed: int = Field(2017, ge=0, le=2**32 - 1)
    start_time: datetime | None = None
    clock: ClockConfig = Field(default_factory=ClockConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    traffic: TrafficConfig = Field(default_factory=TrafficConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    incidents: IncidentConfig = Field(default_factory=IncidentConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)

    @field_validator("start_time")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("start_time must include a timezone (e.g. 2026-01-01T09:00:00Z)")
        return v


def load_config(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> SimConfig:
    """Read the YAML config (defaults if the file is absent) and apply nested overrides."""
    p = Path(path or DEFAULT_CONFIG)
    raw: dict[str, Any] = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}
    return SimConfig.model_validate(deep_merge(raw, overrides or {}))


def deep_merge(base: dict[str, Any], upd: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in upd.items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out
