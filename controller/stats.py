"""
Small statistics helpers for Phase 2 reporting.

wilson_interval: the Wilson score interval for a binomial proportion. Preferred
over the normal (Wald) interval for the small n and near-0/near-1 proportions
these reliability tallies produce (e.g. 30/30 or 0/10), where Wald degenerates.
Deterministic; no external dependencies.
"""

from __future__ import annotations

import math

from dataclasses import dataclass


# z for common two-sided confidence levels.
Z_95 = 1.959963984540054
Z_90 = 1.6448536269514722
Z_99 = 2.5758293035489004


@dataclass(frozen=True)
class ProportionCI:
    successes: int
    n: int
    point: float
    low: float
    high: float
    confidence: float
    method: str = "wilson"

    def as_pct(self, digits: int = 1) -> str:
        return (
            f"{self.point * 100:.{digits}f}% "
            f"[{self.low * 100:.{digits}f}, {self.high * 100:.{digits}f}]"
        )


def wilson_interval(
    successes: int, n: int, z: float = Z_95, confidence: float = 0.95
) -> ProportionCI:
    """Wilson score interval for `successes` out of `n` Bernoulli trials."""

    if n < 0 or successes < 0:
        raise ValueError("successes and n must be non-negative")
    if successes > n:
        raise ValueError("successes cannot exceed n")
    if n == 0:
        return ProportionCI(0, 0, 0.0, 0.0, 1.0, confidence)

    phat = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (phat + z2 / (2 * n)) / denom
    margin = (
        z * math.sqrt((phat * (1.0 - phat) + z2 / (4 * n)) / n)
    ) / denom
    # Round to 10 dp before clamping: kills float noise (e.g. the p=1 upper
    # bound is exactly 1.0 in exact arithmetic but lands at 0.9999999999999999).
    low = max(0.0, round(centre - margin, 10))
    high = min(1.0, round(centre + margin, 10))
    return ProportionCI(successes, n, phat, low, high, confidence)
