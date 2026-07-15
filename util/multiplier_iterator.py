"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Multiplier iterator classes for Suricata tests.

Provide iterator strategies (enumeration and binary search) for determining
the next TRex traffic multiplier to test.
"""

from abc import ABC, abstractmethod
from typing import List

from util.suri_util import MultiplierNotFoundError


class MultiplierIterator(ABC):
    def __init__(self):
        self._finished = False
        self._current_multiplier = None

    @abstractmethod
    def __next__(self) -> float:
        """Return the next multiplier to test, or raise StopIteration."""
        ...

    def __iter__(self):
        return self

    @abstractmethod
    def set_result(self, drop_rate: float):
        """Feed the drop rate from the last run back to the iterator."""
        ...

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    def current_multiplier(self) -> float | None:
        return self._current_multiplier

    @property
    @abstractmethod
    def result(self) -> float | None:
        """The final result (e.g. max multiplier found), or None."""
        ...


class EnumerateMultiplierIterator(MultiplierIterator):
    """Yields multipliers from a static list, one by one."""

    def __init__(self, multipliers: List[float]):
        super().__init__()
        self._multipliers = multipliers
        self._idx = 0

    def __next__(self) -> float:
        if self._idx >= len(self._multipliers):
            self._finished = True
            raise StopIteration
        self._current_multiplier = self._multipliers[self._idx]
        self._idx += 1
        return self._current_multiplier

    def set_result(self, drop_rate: float):
        pass

    @property
    def result(self) -> float | None:
        return None

    def __len__(self):
        return len(self._multipliers)

    @property
    def progress(self) -> tuple[int, int]:
        return (self._idx, len(self._multipliers))


class BinarySearchMultiplierIterator(MultiplierIterator):
    """Yields multipliers using binary search to converge on a target drop rate."""

    def __init__(
        self,
        mini: float,
        maxi: float,
        drop_rate: float,
        precision: float,
    ):
        super().__init__()
        self._mini = mini
        self._maxi = maxi
        self._target_drop_rate = drop_rate
        self._precision = precision
        self._max_multiplier = -1.0
        self._cycle = 0
        self._validate_params()

    def _validate_params(self):
        if self._precision <= 0:
            self._precision = 0.05
            print("[WARNING] Binary search: Precision was <= 0. Setting to 0.05.")
        if self._mini < 0:
            self._mini = 0
            print(
                "[WARNING] Binary search: Minimum multiplier was below 0. Setting to 0."
            )
        if self._maxi < 0:
            self._maxi = 0
            print(
                "[WARNING] Binary search: Maximum multiplier was below 0. Setting to 0."
            )
        if self._mini > self._maxi:
            self._mini, self._maxi = self._maxi, self._mini
            print("[WARNING] Binary search: Max < min. Swapping values.")
        if self._target_drop_rate < 0:
            self._target_drop_rate = 0
            print("[WARNING] Binary search: Drop rate is below 0%. Setting to 0%.")
        if self._target_drop_rate > 100:
            self._target_drop_rate = 100
            print("[WARNING] Binary search: Drop rate is above 100%. Setting to 100%.")

    def __next__(self) -> float:
        if self._finished:
            raise StopIteration

        if self._cycle > 0 and (self._maxi - self._mini) < self._precision:
            self._finished = True
            if self._max_multiplier == -1:
                raise MultiplierNotFoundError(
                    f"No suitable multiplier found in range [{self._mini}, {self._maxi}] "
                    f"with target drop rate {self._target_drop_rate}% after {self._cycle} cycles."
                )
            raise StopIteration

        self._cycle += 1
        self._current_multiplier = (self._mini + self._maxi) / 2
        print(f"\n[PROGRESS] ------ Cycle: {self._cycle} ------- [PROGRESS]")
        return self._current_multiplier

    def set_result(self, drop_rate: float):
        print(f"[INFO] Drop rate: {drop_rate:.4f}%.")

        if drop_rate > self._target_drop_rate:
            self._maxi = self._current_multiplier
        else:
            self._mini = self._current_multiplier
            self._max_multiplier = self._current_multiplier

    @property
    def result(self) -> float | None:
        if not self._finished:
            return None
        return self._max_multiplier if self._max_multiplier != -1 else None


def multiplier_iterator_create(
    b_search: dict | None,
    trex_multipliers: List[float],
) -> MultiplierIterator:
    """Factory: returns the appropriate MultiplierIterator based on config.

    Args:
        b_search: None for enumeration mode, or a dict with keys
                  min, max, drop_rate, precision for binary search.
        trex_multipliers: Static list of multipliers for enumeration mode.

    Returns:
        A MultiplierIterator instance.
    """
    if b_search is None:
        return EnumerateMultiplierIterator(trex_multipliers)
    return BinarySearchMultiplierIterator(
        mini=b_search["min"],
        maxi=b_search["max"],
        drop_rate=b_search["drop_rate"],
        precision=b_search["precision"],
    )
