import json
import logging
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import md5
from pathlib import Path
from typing import Any, Final, Literal, TypedDict, TypeGuard

from iam_action_catalog.access_fetcher import (
    LastAccessFetchResultItemTypeDef,
    LastAccessFetchResultTypeDef,
    list_last_accessed_details,
)
from iam_action_catalog.action_catalog import (
    SCHEMA_VERSION,
    ActionTypeDef,
    GlobalServiceToActions,
)
from iam_action_catalog.utils import unwrap

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


class _CatalogErrorKind(Enum):
    does_not_exist = "does_not_exist"
    invalid_json = "invalid_json"
    malformed_schema = "malformed_schema"
    checksum_mismatch = "checksum_mismatch"
    other = "other"


class _CatalogError(Exception):
    def __init__(self, kind: _CatalogErrorKind, message: str = "") -> None:
        self.kind = kind
        self.message = message
        super().__init__(f"[{kind.value}], {message}")

    def __str__(self) -> str:
        return f"[{self.kind.value}], {self.message}"


class _Metadata(TypedDict):
    schema_version: str
    checksum: str
    generated_timestamp: int


class _Catalog(TypedDict):
    meta: _Metadata
    contents: str


def _is_valid_schema(data: dict[str, Any]) -> TypeGuard[_Catalog]:
    return (
        isinstance(data, dict)
        and set(data.keys()) == {"meta", "contents"}
        and "schema_version" in data["meta"]
        and "generated_timestamp" in data["meta"]
        and data["meta"]["schema_version"] == SCHEMA_VERSION
    )


def _save_catalog(
    output_path: Path, contents: dict[str, list[ActionTypeDef]], timestamp: int
):
    serialized = json.dumps(contents, sort_keys=True)
    checksum = md5(serialized.encode("utf-8")).hexdigest()
    with open(output_path, "w") as out:
        json.dump(
            _Catalog(
                meta={
                    "schema_version": SCHEMA_VERSION,
                    "checksum": checksum,
                    "generated_timestamp": timestamp,
                },
                contents=serialized,
            ),
            out,
        )
    logger.info(f"Catalog saved to {output_path.absolute()}.")


def _retrieve_catalog(path: Path) -> dict[str, list[ActionTypeDef]]:
    try:
        serialized = path.read_text()
    except FileNotFoundError as e:
        raise _CatalogError(
            _CatalogErrorKind.does_not_exist,
            f"Catalog file not found at '{path}'.",
        ) from e

    try:
        catalog = json.loads(serialized)
    except json.JSONDecodeError as e:
        raise _CatalogError(
            _CatalogErrorKind.invalid_json, "Catalog file contains invalid JSON."
        ) from e

    if not _is_valid_schema(catalog):
        raise _CatalogError(
            _CatalogErrorKind.malformed_schema,
            "Catalog file does not conform to the expected schema.",
        )

    serialized_contents = catalog["contents"]
    if (
        md5(serialized_contents.encode("utf-8")).hexdigest()
        != catalog["meta"]["checksum"]
    ):
        raise _CatalogError(
            _CatalogErrorKind.checksum_mismatch,
            "Checksum mismatch between catalog metadata and actual contents.",
        )

    try:
        return json.loads(serialized_contents)
    except json.JSONDecodeError as e:
        raise _CatalogError(
            _CatalogErrorKind.invalid_json, "Catalog contents contain invalid JSON."
        ) from e


@dataclass
class BuildCatalog:
    pass


@dataclass
class ShowCatalog:
    pretty: bool


@dataclass
class ListLastAccessedDetails:
    arn: str
    pretty_print: bool
    aws_access_key_id: str | None
    aws_secret_access_key: str | None
    aws_profile: str | None
    aws_region: str | None
    days_from_last_accessed: int
    only_considered_unused: bool
    output_structure: Literal["list", "dict"]
    exclude_aws_managed: bool


@dataclass
class ParseResult:
    catalog_path: Path
    command: BuildCatalog | ShowCatalog | ListLastAccessedDetails


def parse_args() -> ParseResult:
    parser = ArgumentParser(
        description="Extract AWS IAM action catalog and list potentially unused actions using Access Analyzer data."
    )
    parser.add_argument(
        "--catalog-path",
        type=str,
        required=True,
        help="Path to the local catalog file, which contains parsed IAM action definitions used for analysis.",
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
    catalog_subparser = catalog_parser.add_subparsers(
        dest="command",
        required=True,
        help="Subcommand for `catalog` command. Must be one of: 'show', 'build'.",
    )
    catalog_subparser.add_parser(
        "build", help="Build the IAM action catalog by parsing AWS documentation."
    )

    show_catalog_parser = catalog_subparser.add_parser(
        "show", help="Display the contents of the local IAM action catalog."
    )
    show_catalog_parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print the catalog JSON output."
    )

    list_last_accessed_details = subparsers.add_parser(
        "list-last-accessed-details",
        help="List potentially unused IAM actions based on Access Analyzer data.",
    )
    list_last_accessed_details.add_argument(
        "--arn",
        type=str,
        required=True,
        help="ARN of the IAM role, user, or group to analyze. Both managed and inline policies will be evaluated.",
    )
    list_last_accessed_details.add_argument(
        "--aws-access-key-id",
        type=str,
        help="AWS access key ID. Must be used together with --aws-secret-access-key. Ignored if --aws-profile is set.",
    )

    list_last_accessed_details.add_argument(
        "--aws-secret-access-key",
        type=str,
        help="AWS secret access key. Must be used together with --aws-access-key-id. Ignored if --aws-profile is set.",
    )

    list_last_accessed_details.add_argument(
        "--aws-profile",
        type=str,
        help="AWS named profile to use for credentials. Cannot be used together with --aws-access-key-id or --aws-secret-access-key.",
    )
    list_last_accessed_details.add_argument(
        "--aws-region", type=str, help="AWS region to use. Optional."
    )

    list_last_accessed_details.add_argument(
        "--pretty", action="store_true", help="Pretty-print the output JSON."
    )
    list_last_accessed_details.add_argument(
        "--only-considered-unused",
        action="store_true",
        help="Only include actions that are considered unused.",
    )
    list_last_accessed_details.add_argument(
        "--days-from-last-accessed",
        type=int,
        default=90,
        help="Number of days since last access to consider an action unused. Default: 90.",
    )
    list_last_accessed_details.add_argument(
        "--output-structure",
        choices={"list", "dict"},
        default="list",
        help="Output structure. 'list' produces an array of results; 'dict' maps each ARN to its corresponding result.",
    )
    list_last_accessed_details.add_argument(
        "--exclude-aws-managed",
        action="store_true",
        help="Exclude AWS managed policies (arn:aws:iam::aws:policy/...) from the results.",
    )

    ret = parser.parse_args()

    catalog_path = Path(ret.catalog_path).absolute()
    if ret.command == "build":
        return ParseResult(catalog_path=catalog_path, command=BuildCatalog())
    elif ret.command == "show":
        return ParseResult(
            catalog_path=catalog_path, command=ShowCatalog(pretty=ret.pretty)
        )
    else:
        command = ListLastAccessedDetails(
            arn=ret.arn,
            aws_access_key_id=ret.aws_access_key_id,
            aws_secret_access_key=ret.aws_secret_access_key,
            aws_profile=ret.aws_profile,
            aws_region=ret.aws_region,
            days_from_last_accessed=ret.days_from_last_accessed,
            pretty_print=ret.pretty,
            only_considered_unused=ret.only_considered_unused,
            output_structure=ret.output_structure,
            exclude_aws_managed=ret.exclude_aws_managed,
        )

    return ParseResult(
        catalog_path=Path(ret.catalog_path).absolute(),
        command=command,
    )


def main():
    setup_logger()
    args = parse_args()

    catalog_path = args.catalog_path
    does_not_exist = False
    catalog = None
    try:
        catalog = _retrieve_catalog(catalog_path)
    except _CatalogError as e:
        if e.kind == _CatalogErrorKind.does_not_exist:
            does_not_exist = True
            logger.info("Catalog file not found. Generating a new one...")
            catalog = GlobalServiceToActions.instance().value()
            _save_catalog(
                catalog_path, catalog, timestamp=int(datetime.now().timestamp())
            )
        elif not isinstance(args.command, BuildCatalog):
            logger.exception("Failed to retrieve the catalog")
            sys.exit(1)

    if isinstance(args.command, ListLastAccessedDetails):
        if args.command.aws_profile and (
            args.command.aws_access_key_id or args.command.aws_secret_access_key
        ):
            raise ValueError(
                "Use either --aws-profile or --aws-access-key-id/secret, not both"
            )

        if (
            args.command.aws_access_key_id and not args.command.aws_secret_access_key
        ) or (
            not args.command.aws_access_key_id and args.command.aws_secret_access_key
        ):
            raise ValueError(
                "--aws-access-key-id/secret must be set both or must not be set both"
            )

    if isinstance(args.command, BuildCatalog):
        if not does_not_exist:
            logger.info("Refreshing catalog data...")
            catalog = GlobalServiceToActions.instance().value()
            _save_catalog(
                catalog_path, catalog, timestamp=int(datetime.now().timestamp())
            )
    elif isinstance(args.command, ShowCatalog):
        json.dump(
            unwrap(catalog), sys.stdout, indent=4 if args.command.pretty else None
        )
    elif isinstance(args.command, ListLastAccessedDetails):
        da = args.command
        details = list_last_accessed_details(
            arn=da.arn,
            catalog=unwrap(catalog),
            days_from_last_accessed=da.days_from_last_accessed,
            only_considered_unused=da.only_considered_unused,
            profile_name=da.aws_profile,
            access_key_id=da.aws_access_key_id,
            secret_access_key=da.aws_secret_access_key,
            region=da.aws_region,
        )

        def exclude_aws_managed_policies(
            result: LastAccessFetchResultTypeDef,
        ) -> LastAccessFetchResultTypeDef:
            result["items"] = [
                i
                for i in result["items"]
                if i["kind"] != "attached"
                or not i["name"].startswith("arn:aws:iam::aws:policy")
            ]
            return result

        if da.exclude_aws_managed:
            details = [exclude_aws_managed_policies(d) for d in details]

        if da.output_structure == "list":
            json.dump(details, sys.stdout, indent=4 if da.pretty_print else None)
        else:
            json.dump(
                {d["arn"]: {"items": d["items"]} for d in details},
                sys.stdout,
                indent=4 if da.pretty_print else None,
            )
        sys.stdout.write("\n")
    else:
        raise AssertionError("unreachable")


if __name__ == "__main__":
    main()
