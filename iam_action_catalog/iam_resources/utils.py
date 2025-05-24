import fnmatch
import json
import logging
import re
from typing import Callable

from mypy_boto3_iam.type_defs import (
    PolicyDocumentStatementTypeDef,
    PolicyDocumentTypeDef,
)

from iam_action_catalog.action_catalog import ActionTypeDef

from .types import Action

_ACTION_PATTERN = re.compile(r"^(?P<global>\*)$|^(?P<service>[^:]+):(?P<action>.+)$")

logger = logging.getLogger(__name__)


def get_actions_from_policy_document(
    policy_document: PolicyDocumentTypeDef,
    make_failed_message_prefix: Callable[[str], str],
    catalog_map: dict[str, dict[str, ActionTypeDef]],
) -> set[Action]:
    statement: list[PolicyDocumentStatementTypeDef]
    if isinstance(policy_document, str):
        statement = json.loads(policy_document)["Statement"]
    else:
        statement = policy_document["Statement"]

    ret: set[Action] = set()
    for s in statement:
        actions = s["Action"]
        if not isinstance(actions, list):
            actions = [actions]

        for action in actions:
            (service_namespace, matched_names), failed_reason = _try_expand_action(
                action, catalog_map
            )

            if failed_reason:
                prefix = make_failed_message_prefix(action)
                logger.warning(f"{prefix}: {failed_reason}.")
                continue

            for matched_name in matched_names:
                # Action names in IAM policies are case-insensitive, so we match using lowercase.
                # For output, we use the name from the catalog as it reflects the official casing from AWS documentation.
                action_from_catalog = catalog_map[service_namespace][matched_name]
                ret.add(
                    Action(
                        service_namespace=service_namespace,
                        action_name=action_from_catalog["name"],
                        last_accessed_trackable=action_from_catalog[
                            "last_accessed_trackable"
                        ],
                    )
                )
    return ret


def _try_expand_action(
    action: str, catalog_map: dict[str, dict[str, ActionTypeDef]]
) -> tuple[tuple[str, list[str]], str]:
    match = _ACTION_PATTERN.search(action)
    failed_reason = ""
    matched_name = ""
    service_namespace = ""

    if not match:
        failed_reason = "invalid format (expected service:action)."
    else:
        # In IAM policies, action names like 'ec2:DescribeInstances' are case-insensitive.
        # To ensure consistent matching, the service namespace and action name are normalized to lowercase.
        if match.group("global") == "*":
            failed_reason = "global wildcard is not supported."
        else:
            service_namespace = match.group("service").lower()
            matched_name = match.group("action").lower()

            if "*" in service_namespace:
                failed_reason = "wildcard in service name is not supported."
            elif service_namespace not in catalog_map:
                failed_reason = "unknown service namespace"

    if failed_reason:
        return (("", []), failed_reason)

    matched_names = fnmatch.filter(catalog_map[service_namespace].keys(), matched_name)

    return ((service_namespace, matched_names), "")
