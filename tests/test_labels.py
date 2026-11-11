"""Tests for the explicit label mapping."""
from __future__ import annotations

import pandas as pd
import pytest

from src.preprocessing.labels import (FAMILIES, FINE_LABELS, OBSERVED_RAW_LABELS, UnknownLabelError,
                                      canonical_key, map_label, map_labels)


def test_all_observed_raw_labels_map() -> None:
    assert len(OBSERVED_RAW_LABELS) == 15
    fines = {map_label(r)[0] for r in OBSERVED_RAW_LABELS}
    assert fines == set(FINE_LABELS)
    assert {map_label(r)[1] for r in OBSERVED_RAW_LABELS} == set(FAMILIES)


@pytest.mark.parametrize("raw,fine,family,binary", [
    ("BENIGN", "BENIGN", "Benign", 0),
    ("Web Attack – Sql Injection", "Web Attack - SQL Injection", "WebAttack", 1),
    ("Web Attack - Sql Injection", "Web Attack - SQL Injection", "WebAttack", 1),
    ("Web Attack  –  SQL Injection ", "Web Attack - SQL Injection", "WebAttack", 1),
    ("Web Attack–XSS", "Web Attack - XSS", "WebAttack", 1),
    ("FTP-Patator", "FTP-Patator", "BruteForce", 1),
    ("DoS slowloris", "DoS slowloris", "DoS", 1),
    ("Heartbleed", "Heartbleed", "Heartbleed", 1),
])
def test_variants(raw: str, fine: str, family: str, binary: int) -> None:
    assert map_label(raw) == (fine, family, binary)


def test_replacement_char_is_not_guessed() -> None:
    with pytest.raises(UnknownLabelError, match="U\\+FFFD"):
        map_label("Web Attack � Brute Force")


def test_unknown_label_errors() -> None:
    with pytest.raises(UnknownLabelError, match="unknown label"):
        map_label("DoS Mystery")
    with pytest.raises(UnknownLabelError):
        map_label(float("nan"))  # type: ignore[arg-type]


def test_map_labels_preserves_raw() -> None:
    raw = pd.Series(["BENIGN", "Web Attack – XSS", "DDoS"], index=[10, 11, 12])
    out = map_labels(raw)
    assert out["label_raw"].tolist() == raw.tolist()
    assert out.index.tolist() == [10, 11, 12]
    assert out["label_family"].tolist() == ["Benign", "WebAttack", "DDoS"]
    assert out["label_binary"].tolist() == [0, 1, 1]


def test_canonical_key_does_not_touch_fffd() -> None:
    assert "�" in canonical_key("a � b")
