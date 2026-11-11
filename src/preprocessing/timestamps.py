"""Timestamp parsing with the evidence-backed 12-hour correction (contract §3).

Raw strings are d/m/Y H:M[:S] on a 12-hour clock without AM/PM. Hours in ``pm_hours`` get +12.
Any hour outside ``allowed_hours`` or any unparseable string aborts, because the rule's evidence
would no longer hold.
"""
from __future__ import annotations

import pandas as pd

TS_RE = r"^(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?$"


class TimestampError(ValueError):
    """Raised when timestamps violate the validated format/correction assumptions."""


def parse_and_correct(
    ts_raw: pd.Series,
    pm_hours: tuple[int, int] = (1, 5),
    allowed_hours: tuple[int, ...] = (1, 2, 3, 4, 5, 8, 9, 10, 11, 12),
) -> tuple[pd.Series, pd.Series]:
    """Return (timestamp as datetime64[ns], corrected flag). Does not modify ``ts_raw``."""
    s = ts_raw.astype("string").str.strip()
    p = s.str.extract(TS_RE)
    bad = p[0].isna()
    if bad.any():
        raise TimestampError(f"{int(bad.sum())} unparseable timestamps, e.g. {s[bad].head(3).tolist()}")
    day, month, year, hour, minute = (p[i].astype(int) for i in range(5))
    second = p[5].fillna("0").astype(int)
    disallowed = ~hour.isin(list(allowed_hours))
    if disallowed.any():
        raise TimestampError(f"hours outside validated set {allowed_hours}: "
                             f"{sorted(hour[disallowed].unique().tolist())} (e.g. {s[disallowed].head(3).tolist()})")
    corrected = hour.between(pm_hours[0], pm_hours[1])
    hour24 = hour + 12 * corrected.astype(int)
    ts = pd.to_datetime(pd.DataFrame({"year": year, "month": month, "day": day, "hour": hour24,
                                      "minute": minute, "second": second}))
    return ts.rename("timestamp"), corrected.rename("timestamp_corrected")
