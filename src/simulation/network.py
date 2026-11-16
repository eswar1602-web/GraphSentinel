"""Synthetic network topology: devices, roles, addresses and the services they offer.

Addresses: internal hosts use 10.10.0.0/16 (private); external endpoints use the RFC 5737 documentation ranges
198.51.100.0/24 and 203.0.113.0/24, which are reserved for examples and never routed. Nothing is ever
contacted: addresses are labels on simulated flow records.
"""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np

from src.simulation.config import NetworkConfig

ROLES = ("workstation", "laptop", "app_server", "db_server", "dns_server", "router", "external")
CLIENT_ROLES = ("workstation", "laptop")
INTERNAL_ROLES = tuple(r for r in ROLES if r != "external")
EXTERNAL_NETS = (ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24"))


@dataclass(frozen=True)
class Device:
    id: str
    ip: str
    role: str
    hostname: str
    subnet: str
    services: tuple[int, ...] = field(default_factory=tuple)   # listening (protocol-agnostic) ports

    @property
    def internal(self) -> bool:
        return self.role != "external"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["services"] = list(self.services)
        d["internal"] = self.internal
        return d


SERVICES = {"workstation": (135, 139, 445, 3389), "laptop": (135, 139, 445), "app_server": (22, 80, 443, 8080),
            "db_server": (22, 5432), "dns_server": (22, 53), "router": (22, 161), "external": (53, 80, 123, 443)}


class Network:
    """Deterministic topology for a seed. Device ids are stable strings such as ``ws-03`` or ``ext-05``."""

    def __init__(self, cfg: NetworkConfig, seed: int) -> None:
        self.cfg = cfg
        rng = np.random.default_rng([seed, 1])
        devs: list[Device] = []

        def add(role: str, prefix: str, n: int, subnet: str, base: int) -> None:
            net = ipaddress.ip_network(subnet)
            for i in range(n):
                ip = str(net.network_address + base + i)
                devs.append(Device(f"{prefix}-{i + 1:02d}", ip, role, f"{prefix}-{i + 1:02d}.corp.example",
                                   subnet, SERVICES[role]))

        add("router", "rtr", cfg.routers, "10.10.0.0/24", 1)
        add("workstation", "ws", cfg.workstations, "10.10.1.0/24", 10)
        add("laptop", "lt", cfg.laptops, "10.10.2.0/24", 10)
        add("app_server", "app", cfg.app_servers, "10.10.10.0/24", 10)
        add("db_server", "db", cfg.db_servers, "10.10.10.0/24", 50)
        add("dns_server", "dns", cfg.dns_servers, "10.10.10.0/24", 53)
        # External endpoints: distinct random hosts from the documentation ranges, deterministic for the seed.
        pool = [str(ip) for net in EXTERNAL_NETS for ip in list(net.hosts())]
        picks = rng.choice(len(pool), size=cfg.external_endpoints, replace=False)
        for i, k in enumerate(sorted(picks)):
            ip = pool[int(k)]
            devs.append(Device(f"ext-{i + 1:02d}", ip, "external", f"ext-{i + 1:02d}.example.net",
                               "198.51.100.0/24" if ip.startswith("198.51.100.") else "203.0.113.0/24",
                               SERVICES["external"]))
        self.devices: dict[str, Device] = {d.id: d for d in devs}
        self.by_ip: dict[str, Device] = {d.ip: d for d in devs}
        if len(self.by_ip) != len(self.devices):
            raise AssertionError("duplicate device addresses")
        ext = self.role("external")
        # Routine traffic uses all but the last two external endpoints; those two are never contacted by normal
        # traffic, so the scenarios can use them as rare destinations. The detector does not read this split:
        # it learns which pairs are normal from the warm-up baseline.
        self.common_external = ext[:-2]
        self.rare_external = ext[-2:]
        self.admin_workstation = self.role("workstation")[0]

    def role(self, role: str) -> list[Device]:
        return [d for d in self.devices.values() if d.role == role]

    def clients(self) -> list[Device]:
        return [d for d in self.devices.values() if d.role in CLIENT_ROLES]

    def internal(self) -> list[Device]:
        return [d for d in self.devices.values() if d.internal]

    def get(self, device_id: str) -> Device:
        if device_id not in self.devices:
            raise KeyError(f"unknown device '{device_id}'")
        return self.devices[device_id]

    def to_dict(self) -> dict[str, Any]:
        return {"devices": [d.to_dict() for d in self.devices.values()],
                "counts": {r: len(self.role(r)) for r in ROLES},
                "admin_workstation": self.admin_workstation.id,
                "address_note": "internal 10.10.0.0/16; external endpoints from RFC 5737 documentation ranges (never routed)"}
