"""Time-ordered group splits with a purge gap (contract §5).

Within each group, rows are sorted by (timestamp, source_file, raw_row) and cut by rank.
Purge rule for groups with n >= min_group_size_for_purge: for each cut, let t_cut be the timestamp
of the first row of the later split; rows of the earlier split with timestamp >= t_cut - gap are
purged. This guarantees  min(ts later split) - max(ts earlier split) > gap  at the recorded resolution.
If purging would empty a split (dense bursts recorded at minute resolution, e.g. PortScan), the group
falls back to **whole-minute-boundary splitting** (contract §5.1, decision D1): splits consist of whole
timestamp minutes in chronological order, and one entire boundary minute is dropped at every cut, so no
recorded minute is shared between splits and min(later) - max(earlier) > 60 s. Boundary minutes are chosen by
exhaustive search minimizing  sum_j |n_j/n - f_j| + n_dropped/n  (ties -> earliest). Exact ratios are
not forced. Only if that is impossible too (fewer than 2k-1 distinct minutes) is the group cut by rank
and flagged ``purge_infeasible``.

Row status values:
  gap_applied   group used the purge gap (row kept)
  purged        row removed by the purge gap (excluded from every split; kept in metadata)
  minute_boundary          group split on whole-minute boundaries (row kept)
  boundary_minute_dropped  row in a dropped boundary minute (split 'purged'; kept in metadata)
  no_purge_gap  group smaller than min_group_size_for_purge (weaker temporal protection)
  purge_infeasible  neither purge nor minute-boundary split possible; cut by rank only
  too_small     fewer rows than splits; all rows assigned to the first split
  holdout       rows assigned wholesale by day (day-holdout test days)
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd


def rank_boundaries(n: int, fractions: list[float]) -> list[int]:
    """Start index of each split after the first, ensuring every split has >= 1 row (requires n >= k)."""
    k = len(fractions)
    cum = np.cumsum(fractions)[:-1]
    b = [int(np.floor(c * n)) for c in cum]
    out, prev = [], 0
    for j, x in enumerate(b, start=1):
        x = min(max(x, prev + 1), n - (k - j))
        out.append(x)
        prev = x
    return out


def minute_boundary_split(ts: np.ndarray, fractions: list[float]) -> np.ndarray | None:
    """Whole-minute split of a time-sorted group; -1 marks dropped boundary-minute rows. None if infeasible."""
    n, k = len(ts), len(fractions)
    minutes = ts.astype("datetime64[m]")
    _, counts = np.unique(minutes, return_counts=True)
    m = len(counts)
    if m < 2 * k - 1:
        return None
    cum = np.concatenate([[0], np.cumsum(counts)])        # cum[i] = rows in minutes [0, i)
    f = np.asarray(fractions, dtype=float)
    best: tuple[float, tuple[int, ...]] | None = None

    def search(j: int, start: int, chosen: tuple[int, ...]) -> None:
        nonlocal best
        if j == k - 1:
            sizes = [cum[chosen[0]]] + [cum[chosen[i]] - cum[chosen[i - 1] + 1] for i in range(1, k - 1)] \
                + [n - cum[chosen[-1] + 1]]
            dropped = sum(int(counts[b]) for b in chosen)
            score = float(np.abs(np.asarray(sizes) / n - f).sum() + dropped / n)
            if best is None or score < best[0] - 1e-12:
                best = (score, chosen)
            return
        # boundary minute b: >=1 minute before it (or after previous boundary), room for remaining splits after
        for b in range(start, m - 2 * (k - 1 - j) + 1):
            search(j + 1, b + 2, (*chosen, b))

    search(0, 1, ())
    assert best is not None
    split = np.empty(n, dtype=int)
    minute_idx = np.repeat(np.arange(m), counts)
    bounds = best[1]
    seg = np.searchsorted(np.asarray(bounds), minute_idx, side="right")   # split index by minute position
    split[:] = seg
    split[np.isin(minute_idx, bounds)] = -1
    return split


def split_group(ts: np.ndarray, fractions: list[float], gap: np.timedelta64, min_n: int
                ) -> tuple[np.ndarray, np.ndarray]:
    """Split one group already sorted by time. Returns (split index per row, -1 = purged; status per row)."""
    n, k = len(ts), len(fractions)
    if n < k:
        return np.zeros(n, dtype=int), np.full(n, "too_small", dtype=object)
    bounds = rank_boundaries(n, fractions)
    edges = [0, *bounds, n]
    split = np.empty(n, dtype=int)
    for j in range(k):
        split[edges[j]:edges[j + 1]] = j
    if n < min_n:
        return split, np.full(n, "no_purge_gap", dtype=object)
    purged = split.copy()
    for j, b in enumerate(bounds):
        t_cut = ts[b]
        earlier = purged == j
        purged[earlier & (ts >= t_cut - gap)] = -1
    if any(not (purged == j).any() for j in range(k)):
        mb = minute_boundary_split(ts, fractions)
        if mb is None:
            return split, np.full(n, "purge_infeasible", dtype=object)
        return mb, np.where(mb == -1, "boundary_minute_dropped", "minute_boundary").astype(object)
    status = np.where(purged == -1, "purged", "gap_applied").astype(object)
    return purged, status


def assign_group_splits(meta: pd.DataFrame, group_cols: list[str], fractions: list[float], names: list[str],
                        gap_seconds: int, min_n: int) -> tuple[pd.Series, pd.Series]:
    """Apply split_group per group. Returns (split name or 'purged', status) aligned to meta.index."""
    if abs(sum(fractions) - 1) > 1e-9 or len(fractions) != len(names):
        raise ValueError("fractions must sum to 1 and match names")
    gap = np.timedelta64(int(gap_seconds), "s")
    split = pd.Series(pd.NA, index=meta.index, dtype="object")
    status = pd.Series(pd.NA, index=meta.index, dtype="object")
    for _, g in meta.groupby(group_cols, sort=True):
        g = g.sort_values(["timestamp", "source_file", "raw_row"], kind="mergesort")
        s, st = split_group(g["timestamp"].to_numpy(), fractions, gap, min_n)
        split.loc[g.index] = np.where(s == -1, "purged", np.array(names, dtype=object)[np.clip(s, 0, None)])
        status.loc[g.index] = st
    return split, status


def primary_split(meta: pd.DataFrame, cfg: dict[str, Any]) -> tuple[pd.Series, pd.Series]:
    """Time-ordered 70/15/15 within each (day, label_fine) group."""
    return assign_group_splits(meta, ["day", "label_fine"], cfg["fractions"], cfg["names"],
                               cfg["purge_gap_seconds"], cfg["min_group_size_for_purge"])


def dayholdout_split(meta: pd.DataFrame, cfg: dict[str, Any]) -> tuple[pd.Series, pd.Series]:
    """Train/val from train_days (time-ordered within (day, label_fine)); all test_days rows -> test."""
    days = set(cfg["train_days"]) | set(cfg["test_days"])
    if set(cfg["train_days"]) & set(cfg["test_days"]):
        raise ValueError("train_days and test_days overlap")
    unknown = set(meta["day"].unique()) - days
    if unknown:
        raise ValueError(f"days not assigned to day-holdout: {sorted(unknown)}")
    split = pd.Series("test", index=meta.index, dtype="object")
    status = pd.Series("holdout", index=meta.index, dtype="object")
    tr = meta["day"].isin(cfg["train_days"])
    s, st = assign_group_splits(meta.loc[tr], ["day", "label_fine"], cfg["trainval_fractions"], ["train", "val"],
                                cfg["purge_gap_seconds"], cfg["min_group_size_for_purge"])
    split.loc[tr], status.loc[tr] = s, st
    return split, status
