from typing import TypeVar

T = TypeVar("T")


def unwrap(value: T | None) -> T:
    assert value is not None
    return value
