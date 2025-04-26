import json
import logging
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Final, TypedDict, TypeGuard

from iam_action_catalog.action_catalog import (
    SCHEMA_VERSION,
    ActionTypeDef,
    GlobalServiceToActions,
)

CACHE_EXPIRATION_SECONDS: Final[int] = 60 * 60 * 24


class LevelBasedStreamHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()

    def emit(self, record):
        if record.levelno < logging.WARNING:
            self.stream = sys.stdout
        else:
            self.stream = sys.stderr
        super().emit(record)


logger = logging.getLogger("iam_action_catalog")


def setup_logger(level: int = logging.INFO):
    logger.setLevel(level)

    handler = LevelBasedStreamHandler()
    formatter = logging.Formatter(
        fmt="[{asctime}] [{levelname}] {message}",
        datefmt="%Y-%m-%d %H:%M:%S",
        style="{",
    )
    handler.setFormatter(formatter)

    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False


class _CacheErrorKind(Enum):
    does_not_exist = "does_not_exist"
    broken = "broken"
    malformed_schema = "malformed_schema"
    expired = "expired"
    other = "other"


class _CacheError(Exception):
    def __init__(self, kind: _CacheErrorKind, message: str = "") -> None:
        self.kind = kind
        self.message = message
        super().__init__(f"[{kind.value}], {message}")

    def __str__(self) -> str:
        return f"[{self.kind.value}], {self.message}"


class _Metadata(TypedDict):
    schema_version: str
    generated_timestamp: int


class _Cache(TypedDict):
    meta: _Metadata
    actions: dict[str, list[ActionTypeDef]]


def _is_valid_cache_schema(data: dict[str, Any]) -> TypeGuard[_Cache]:
    return (
        isinstance(data, dict)
        and "meta" in data
        and "schema_version" in data["meta"]
        and "generated_timestamp" in data["meta"]
        and "actions" in data
        and isinstance(data["actions"], dict)
        and data["meta"]["schema_version"] == SCHEMA_VERSION
    )


def _make_cache(
    output_path: Path, actions: dict[str, list[ActionTypeDef]], timestamp: int
) -> _Cache:
    cache = _Cache(
        meta={
            "schema_version": SCHEMA_VERSION,
            "generated_timestamp": timestamp,
        },
        actions=actions,
    )
    output_path.write_text(json.dumps(cache))
    return cache


def _retrieve_cache(path: Path) -> _Cache:
    try:
        cache_str = path.read_text()
    except FileNotFoundError as e:
        raise _CacheError(
            _CacheErrorKind.does_not_exist,
            f"Cache does not exist at specified path `{path}`",
        ) from e

    try:
        cache = json.loads(cache_str)
    except json.JSONDecodeError as e:
        raise _CacheError(_CacheErrorKind.broken, "The cache is broken") from e

    if not _is_valid_cache_schema(cache):
        raise _CacheError(_CacheErrorKind.broken, "The cache is malformed")

    now_timestamp = int(datetime.now().timestamp())
    if now_timestamp - cache["meta"]["generated_timestamp"] > CACHE_EXPIRATION_SECONDS:
        raise _CacheError(_CacheErrorKind.expired, "the cache is expired")

    return cache


@dataclass
class ParseResult:
    cache_path: Path
    rebuild_cache: bool
    pretty_print: bool


def parse_args() -> ParseResult:
    parser = ArgumentParser()
    parser.add_argument("--cache-path", type=str, required=True)
    parser.add_argument("--rebuild-cache", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    ret = parser.parse_args()

    return ParseResult(
        cache_path=Path(ret.cache_path).absolute(),
        rebuild_cache=ret.rebuild_cache,
        pretty_print=ret.pretty,
    )


def main():
    setup_logger()
    args = parse_args()

    if args.rebuild_cache:
        logger.info("`--rebuild-cache` option specified. Rebuilding cache...")
        obj = GlobalServiceToActions.instance()
        cache = _make_cache(
            args.cache_path,
            actions=obj.value(),
            timestamp=int(datetime.now().timestamp()),
        )
    else:
        try:
            cache = _retrieve_cache(args.cache_path)
        except _CacheError as e:
            logger.warning(f"{e}. Building cache...")
            obj = GlobalServiceToActions.instance()
            cache = _make_cache(
                args.cache_path,
                actions=obj.value(),
                timestamp=int(datetime.now().timestamp()),
            )

    json.dump(cache, sys.stdout, indent=4 if args.pretty_print else None)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
