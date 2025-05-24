import fnmatch
import json
import logging
import re
import threading
from typing import Callable, Protocol, TypeAlias

from mypy_boto3_iam.type_defs import (
    PolicyDocumentStatementTypeDef,
    PolicyDocumentTypeDef,
)

from iam_action_catalog.action_catalog import Catalog
from iam_action_catalog.api import IAMClient
from iam_action_catalog.utils import mask_arn, unwrap

from .types import Action

logger = logging.getLogger(__name__)

ServiceNamespace: TypeAlias = str
PolicyArn: TypeAlias = str
ActionName: TypeAlias = str

_ACTION_PATTERN = re.compile(r"^(?P<global>\*)$|^(?P<service>[^:]+):(?P<action>.+)$")


class PolicyProtocol(Protocol):
    @property
    def arn(self) -> str: ...

    def get_actions(self) -> set[Action]: ...


class Policy(PolicyProtocol):
    _lock: threading.Lock = threading.Lock()

    def __init__(
        self, arn: str, make_client: Callable[[], IAMClient], catalog: Catalog
    ) -> None:
        self._arn = arn
        self._make_client = make_client
        self._catalog_map = {
            service_namespace.lower(): {a["name"].lower(): a for a in actions}
            for service_namespace, actions in catalog.items()
        }

    def _ensure_client(self) -> IAMClient:
        with self._lock:
            client = getattr(self, "__client", None)
            if client is None:
                client = self._make_client()
                setattr(self, "__client", client)
            return client

    @property
    def is_aws_managed(self) -> bool:
        return self._arn.startswith("arn:aws:iam::aws:policy")

    @property
    def arn(self) -> str:
        return self._arn

    def get_actions(self) -> set[Action]:
        client = self._ensure_client()
        res = client.get_policy(PolicyArn=self._arn)
        version = unwrap(res["Policy"].get("DefaultVersionId"))
        res = client.get_policy_version(PolicyArn=self._arn, VersionId=version)
        policy_document = res["PolicyVersion"].get("Document")

        if not policy_document:
            return set()

        return self._get_actions_from_policy_document(
            policy_document,
            lambda action: f'Skipping action "{action}" in policy "{mask_arn(self._arn)}"',
        )

    def _get_actions_from_policy_document(
        self,
        policy_document: PolicyDocumentTypeDef,
        make_failed_message_prefix: Callable[[str], str],
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
                (service_namespace, matched_names), failed_reason = (
                    self._try_expand_action(action)
                )

                if failed_reason:
                    prefix = make_failed_message_prefix(action)
                    logger.warning(f"{prefix}: {failed_reason}.")
                    continue

                for matched_name in matched_names:
                    # Action names in IAM policies are case-insensitive, so we match using lowercase.
                    # For output, we use the name from the catalog as it reflects the official casing from AWS documentation.
                    action_from_catalog = self._catalog_map[service_namespace][
                        matched_name
                    ]
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
        self, action: str
    ) -> tuple[tuple[ServiceNamespace, list[ActionName]], str]:
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
                elif service_namespace not in self._catalog_map:
                    failed_reason = "unknown service namespace"

        if failed_reason:
            return (("", []), failed_reason)

        matched_names = fnmatch.filter(
            self._catalog_map[service_namespace].keys(), matched_name
        )

        return ((service_namespace, matched_names), "")


def make_policy(
    arn: str,
    make_client: Callable[[], IAMClient],
    catalog: Catalog,
) -> PolicyProtocol:
    return Policy(arn, make_client, catalog)
