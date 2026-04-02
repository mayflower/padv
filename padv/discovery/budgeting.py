from __future__ import annotations

from collections import deque
from typing import Callable, Iterable, TypeVar


T = TypeVar("T")


def select_fair_share(items: Iterable[T], *, key_fn: Callable[[T], str], limit: int) -> list[T]:
    if limit <= 0:
        return []

    buckets: dict[str, deque[T]] = {}
    class_order: list[str] = []
    for item in items:
        key = key_fn(item)
        if key not in buckets:
            buckets[key] = deque()
            class_order.append(key)
        buckets[key].append(item)

    selected: list[T] = []
    while len(selected) < limit:
        made_progress = False
        for key in class_order:
            bucket = buckets[key]
            if not bucket:
                continue
            selected.append(bucket.popleft())
            made_progress = True
            if len(selected) >= limit:
                break
        if not made_progress:
            break
    return selected
