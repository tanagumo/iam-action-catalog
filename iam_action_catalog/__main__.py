import json
import logging
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Final, Literal, TypedDict, TypeGuard

from iam_action_catalog.action_catalog import (
    SCHEMA_VERSION,
    ActionTypeDef,
    GlobalServiceToActions,
)
from iam_action_catalog.iam import list_last_accessed_details

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
class Catalog:
    tag: Literal["catalog"]
    pretty_print: bool


@dataclass
class ListLastAccessedDetails:
    tag: Literal["list_last_accessed_details"]
    role_arn: str
    pretty_print: bool
    aws_access_key_id: str | None
    aws_secret_access_key: str | None
    aws_profile: str | None
    aws_region: str | None
    days_from_last_accessed: int
    only_considered_unused: bool


@dataclass
class ParseResult:
    cache_path: Path
    rebuild_cache: bool
    subcommand: Catalog | ListLastAccessedDetails


def parse_args() -> ParseResult:
    parser = ArgumentParser(
        description="Extract AWS IAM action catalog and list potentially unused actions using Access Analyzer data."
    )
    parser.add_argument(
        "--cache-path",
        type=str,
        required=True,
        help="Path to the local cache file (used to store parsed IAM documentation).",
    )
    parser.add_argument(
        "--rebuild-cache",
        action="store_true",
        help="Force re-parsing of the IAM documentation even if the cache exists.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Subcommand to run. Must be one of: 'catalog', 'list-last-accessed-details'.",
    )

    catalog_parser = subparsers.add_parser(
        "catalog",
        help="Parse AWS IAM documentation and output the full action catalog.",
    )
    catalog_parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print the output JSON."
    )

    list_last_accessed_details = subparsers.add_parser(
        "list-last-accessed-details",
        help="List actions in the role's policies that are considered unused based on Access Analyzer data.",
    )
    list_last_accessed_details.add_argument(
        "--role-arn",
        type=str,
        required=True,
        help="ARN of the IAM role whose attached policies will be analyzed.",
    )
    list_last_accessed_details.add_argument(
        "--aws-access-key-id",
        type=str,
        help="AWS access key ID (optional, used instead of profile).",
    )

    list_last_accessed_details.add_argument(
        "--aws-secret-access-key",
        type=str,
        help="AWS secret access key (optional, used instead of profile).",
    )

    list_last_accessed_details.add_argument(
        "--aws-profile",
        type=str,
        help="AWS named profile to use for credentials (optional).",
    )
    list_last_accessed_details.add_argument(
        "--aws-region", type=str, help="AWS region to use (optional)."
    )

    list_last_accessed_details.add_argument(
        "--pretty", action="store_true", help="Pretty-print the output JSON."
    )
    list_last_accessed_details.add_argument(
        "--only-considered-unused",
        action="store_true",
        help="If set, only outputs actions considered unused.",
    )
    list_last_accessed_details.add_argument(
        "--days-from-last-accessed",
        type=int,
        default=90,
        help="Threshold in days to consider an action unused if it has not been accessed. Default is 90.",
    )

    ret = parser.parse_args()

    if ret.command == "catalog":
        subcommand = Catalog(tag="catalog", pretty_print=ret.pretty)
    else:
        subcommand = ListLastAccessedDetails(
            tag="list_last_accessed_details",
            role_arn=ret.role_arn,
            aws_access_key_id=ret.aws_access_key_id,
            aws_secret_access_key=ret.aws_secret_access_key,
            aws_profile=ret.aws_profile,
            aws_region=ret.aws_region,
            days_from_last_accessed=ret.days_from_last_accessed,
            pretty_print=ret.pretty,
            only_considered_unused=ret.only_considered_unused,
        )

    return ParseResult(
        cache_path=Path(ret.cache_path).absolute(),
        rebuild_cache=ret.rebuild_cache,
        subcommand=subcommand,
    )


def main():
    setup_logger()
    args = parse_args()

    if args.subcommand.tag == "list_last_accessed_details":
        if args.subcommand.aws_profile and (
            args.subcommand.aws_access_key_id or args.subcommand.aws_secret_access_key
        ):
            raise ValueError(
                "Use either --aws-profile or --aws-access-key-id/secret, not both"
            )

        if (
            args.subcommand.aws_access_key_id
            and not args.subcommand.aws_secret_access_key
        ) or (
            not args.subcommand.aws_access_key_id
            and args.subcommand.aws_secret_access_key
        ):
            raise ValueError(
                "--aws-access-key-id/secret must be set both or must not be set both"
            )

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

    if args.subcommand.tag == "catalog":
        catalog = args.subcommand
        json.dump(cache, sys.stdout, indent=4 if catalog.pretty_print else None)
        sys.stdout.write("\n")
    else:
        da = args.subcommand
        ret = list_last_accessed_details(
            da.role_arn,
            cache["actions"],
            profile_name=da.aws_profile,
            access_key_id=da.aws_access_key_id,
            secret_access_key=da.aws_secret_access_key,
            days_from_last_accessed=da.days_from_last_accessed,
        )

        ret = (
            ret
            if not da.only_considered_unused
            else {
                k: [d for d in details if d["considered_unused"]]
                for k, details in ret.items()
            }
        )
        json.dump(ret, sys.stdout, indent=4 if da.pretty_print else None)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
