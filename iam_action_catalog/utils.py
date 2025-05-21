import re
from typing import TypeVar, overload

from iam_action_catalog.settings import settings

T = TypeVar("T")


def unwrap(value: T | None) -> T:
    assert value is not None
    return value


@overload
def mask_arn(arn: None) -> None: ...


@overload
def mask_arn(arn: str) -> str: ...


def mask_arn(arn: str | None) -> str | None:
    if arn is None:
        return None

    if not settings.mask_arn:
        return arn

    return re.sub(r"arn:aws:iam::(\d{4})\d{8}:", r"arn:aws:iam::\1xxxxxxxx:", arn)
