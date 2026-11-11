"""Explicit CICIDS2017 label mapping: raw string -> fine / family / binary.

Rules (dataset contract §2):
- ``label_raw`` is preserved exactly as decoded; this module never modifies it.
- Lookup is by an explicit table. ``canonical_key`` only folds *typographic* variation that
  the audit observed or that is unambiguous: surrounding/repeated whitespace, en/em dash and
  minus sign vs ASCII hyphen, and letter case (e.g. "Sql" vs "SQL").
- U+FFFD (replacement character) is deliberately NOT folded: it means bytes were lost while
  decoding, so the original character is unknown. Such labels raise ``UnknownLabelError``.
- Any label whose key is not in the table raises ``UnknownLabelError``.
"""
from __future__ import annotations

import re

import pandas as pd

# Exact raw strings observed in TrafficLabelling by the audit (reports/data_audit/audit_traffic_labelling.json).
OBSERVED_RAW_LABELS: tuple[str, ...] = (
    "BENIGN", "DoS Hulk", "PortScan", "DDoS", "DoS GoldenEye", "FTP-Patator", "SSH-Patator",
    "DoS slowloris", "DoS Slowhttptest", "Bot", "Web Attack – Brute Force", "Web Attack – XSS",
    "Infiltration", "Web Attack – Sql Injection", "Heartbleed",
)

FAMILIES: tuple[str, ...] = ("Benign", "DoS", "DDoS", "PortScan", "Bot", "WebAttack", "BruteForce",
                             "Infiltration", "Heartbleed")

_DASHES = re.compile("[‐‑‒–—−]")
_WS = re.compile(r"\s+")
_HYPHEN_SPACING = re.compile(r"\s*-\s*")


class UnknownLabelError(ValueError):
    """Raised when a raw label is not in the explicit mapping table."""


def canonical_key(raw: str) -> str:
    """Typographic normalization used only as a lookup key (never stored as the label)."""
    s = _DASHES.sub("-", raw)
    s = _WS.sub(" ", s).strip()
    s = _HYPHEN_SPACING.sub(" - ", s) if " " in s else s  # "Web Attack–XSS" -> "Web Attack - XSS"; keeps "FTP-Patator"
    return s.casefold()


# key -> (fine, family). Fine names are the canonical display names used in all reports.
_TABLE: dict[str, tuple[str, str]] = {
    "benign": ("BENIGN", "Benign"),
    "dos hulk": ("DoS Hulk", "DoS"),
    "dos goldeneye": ("DoS GoldenEye", "DoS"),
    "dos slowloris": ("DoS slowloris", "DoS"),
    "dos slowhttptest": ("DoS Slowhttptest", "DoS"),
    "ddos": ("DDoS", "DDoS"),
    "portscan": ("PortScan", "PortScan"),
    "bot": ("Bot", "Bot"),
    "ftp-patator": ("FTP-Patator", "BruteForce"),
    "ssh-patator": ("SSH-Patator", "BruteForce"),
    "web attack - brute force": ("Web Attack - Brute Force", "WebAttack"),
    "web attack - xss": ("Web Attack - XSS", "WebAttack"),
    "web attack - sql injection": ("Web Attack - SQL Injection", "WebAttack"),
    "infiltration": ("Infiltration", "Infiltration"),
    "heartbleed": ("Heartbleed", "Heartbleed"),
}

FINE_LABELS: tuple[str, ...] = tuple(v[0] for v in _TABLE.values())


def map_label(raw: str) -> tuple[str, str, int]:
    """Map one raw label to (fine, family, binary). Raises UnknownLabelError if unmapped."""
    if not isinstance(raw, str):
        raise UnknownLabelError(f"label is not a string: {raw!r}")
    if "�" in raw:
        raise UnknownLabelError(f"label contains U+FFFD (lost bytes during decoding), refusing to guess: {raw!r}")
    key = canonical_key(raw)
    if key not in _TABLE:
        cps = [f"U+{ord(c):04X}" for c in raw if ord(c) > 127]
        raise UnknownLabelError(f"unknown label {raw!r} (key {key!r}, non-ASCII {cps}); add it explicitly to the table")
    fine, family = _TABLE[key]
    return fine, family, int(family != "Benign")


def map_labels(raw: pd.Series) -> pd.DataFrame:
    """Vectorized mapping; returns columns label_raw, label_fine, label_family, label_binary."""
    uniques = pd.unique(raw)
    lut = {u: map_label(u) for u in uniques}
    mapped = raw.map(lut)
    return pd.DataFrame({
        "label_raw": raw.values,
        "label_fine": [m[0] for m in mapped],
        "label_family": [m[1] for m in mapped],
        "label_binary": [m[2] for m in mapped],
    }, index=raw.index)
