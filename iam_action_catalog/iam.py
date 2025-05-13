import json
import logging
import os
import time
from concurrent import futures
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable, Literal, TypedDict, TypeVar

import boto3
from mypy_boto3_iam import IAMClient
from mypy_boto3_iam.type_defs import (
    GetServiceLastAccessedDetailsRequestTypeDef,
    ListAttachedRolePoliciesRequestTypeDef,
    ServiceLastAccessedTypeDef,
    TrackedActionLastAccessedTypeDef,
)

from iam_action_catalog.action_catalog import ActionTypeDef, Catalog

logger = logging.getLogger(__name__)

T = TypeVar("T")


def unwrap(value: T | None) -> T:
    assert value is not None
    return value


@dataclass(frozen=True)
class Action:
    service_namespace: str
    action_name: str
    last_accessed_trackable: bool


class GetLastAccessedDetailError(Exception):
    def __init__(
        self,
        policy_arn: str,
        error_code: str,
        error_message: str,
    ) -> None:
        self.policy_arn = policy_arn
        self.error_code = error_code
        self.error_message = error_message


@dataclass
class LastAccessedDetail:
    action_name: str
    service_name: str
    service_namespace: str
    granularity: Literal["service", "action"]
    service_level_last_authenticated: datetime | None
    service_level_last_authenticated_entity: str | None
    service_level_last_authenticated_region: str | None
    action_level_last_accessed: datetime | None
    action_level_last_authenticated_entity: str | None
    action_level_last_authenticated_region: str | None
    considered_unused: bool
    considered_unused_reason: str | None
    considered_not_unused_reason: str | None


def _make_message_for_considered_not_unused_reason(
    trackable: bool, granularity: Literal["service", "action"], days: int
) -> str:
    if not trackable:
        return "This action is not tracked by Access Analyzer and cannot be evaluated."

    if granularity == "action":
        return (
            f"This action was accessed at the action level within the past {days} days."
        )

    return (
        "This action has no recent action-level access record, but "
        f"the service was accessed within the past {days} days"
    )


class LastAccessedDetailTypeDef(TypedDict):
    action_name: str
    service_name: str
    service_namespace: str
    granularity: Literal["service", "action"]
    service_level_last_authenticated: str | None
    service_level_last_authenticated_entity: str | None
    service_level_last_authenticated_region: str | None
    action_level_last_accessed: str | None
    action_level_last_authenticated_entity: str | None
    action_level_last_authenticated_region: str | None
    considered_unused: bool
    considered_unused_reason: str | None
    considered_not_unused_reason: str | None


def _to_last_accessed_detail_type_def(
    detail: LastAccessedDetail,
) -> LastAccessedDetailTypeDef:
    return LastAccessedDetailTypeDef(
        action_name=detail.action_name,
        service_name=detail.service_name,
        service_namespace=detail.service_namespace,
        granularity=detail.granularity,
        service_level_last_authenticated=detail.service_level_last_authenticated.isoformat()
        if detail.service_level_last_authenticated
        else None,
        service_level_last_authenticated_entity=detail.service_level_last_authenticated_entity,
        service_level_last_authenticated_region=detail.service_level_last_authenticated_region,
        action_level_last_accessed=detail.action_level_last_accessed.isoformat()
        if detail.action_level_last_accessed
        else None,
        action_level_last_authenticated_entity=detail.action_level_last_authenticated_entity,
        action_level_last_authenticated_region=detail.action_level_last_authenticated_region,
        considered_unused=detail.considered_unused,
        considered_unused_reason=detail.considered_unused_reason,
        considered_not_unused_reason=detail.considered_not_unused_reason,
    )


def _get_last_accessed_details(
    make_client: Callable[[], IAMClient],
    policy_arn: str,
    action_map: dict[str, list[Action]],
    days_since_last_accessed: int,
    at: datetime,
) -> list[LastAccessedDetail]:
    client = make_client()
    res = client.generate_service_last_accessed_details(
        Arn=policy_arn, Granularity="ACTION_LEVEL"
    )
    job_id = res["JobId"]

    service_to_last_accessed: dict[str, ServiceLastAccessedTypeDef] = {}
    action_to_last_accessed: dict[str, TrackedActionLastAccessedTypeDef] = {}

    marker = None
    while marker is None or marker:
        kwargs = GetServiceLastAccessedDetailsRequestTypeDef(JobId=job_id)
        if marker:
            kwargs["Marker"] = marker
        res = client.get_service_last_accessed_details(**kwargs)
        if res["JobStatus"] == "COMPLETED":
            for s in res["ServicesLastAccessed"]:
                if s["ServiceNamespace"] not in service_to_last_accessed:
                    service_to_last_accessed[s["ServiceNamespace"]] = s

                for t in s.get("TrackedActionsLastAccessed", []):
                    key = f"{s['ServiceNamespace']}:{unwrap(t.get('ActionName'))}"
                    action_to_last_accessed[key] = t

            marker = res.get("Marker", "")

        if res["JobStatus"] == "FAILED":
            logger.error(f"Access detail fetch failed for {policy_arn}")
            error = res.get("Error", {})
            raise GetLastAccessedDetailError(
                policy_arn,
                error_code=error.get("Code", "unkown"),
                error_message=error.get("Message", "unkown"),
            )
        if res["JobStatus"] == "IN_PROGRESS":
            time.sleep(1)

    seconds_since_last_accessed = days_since_last_accessed * 86400
    details = []

    for service_namespace, actions in action_map.items():
        for action in actions:
            service_last_accessed = service_to_last_accessed[service_namespace]

            considered_unused = action.last_accessed_trackable and (
                "LastAuthenticated" not in service_last_accessed
                or (
                    at.timestamp()
                    - service_last_accessed["LastAuthenticated"].timestamp()
                )
                > seconds_since_last_accessed
            )

            service_namespace = service_last_accessed["ServiceNamespace"]

            detail = LastAccessedDetail(
                action_name=action.action_name,
                service_name=service_last_accessed["ServiceName"],
                service_namespace=service_last_accessed["ServiceNamespace"],
                service_level_last_authenticated=service_last_accessed.get(
                    "LastAuthenticated"
                ),
                granularity="service",
                service_level_last_authenticated_entity=service_last_accessed.get(
                    "LastAuthenticatedEntity"
                ),
                service_level_last_authenticated_region=service_last_accessed.get(
                    "LastAuthenticatedRegion"
                ),
                action_level_last_accessed=None,
                action_level_last_authenticated_entity=None,
                action_level_last_authenticated_region=None,
                considered_unused=considered_unused,
                considered_unused_reason=(
                    "This action is tracked by Access Analyzer "
                    "and has not been accessed in the past "
                    f"{days_since_last_accessed} days."
                )
                if considered_unused is True
                else None,
                considered_not_unused_reason=_make_message_for_considered_not_unused_reason(
                    action.last_accessed_trackable, "service", days_since_last_accessed
                )
                if considered_unused is False
                else None,
            )

            if action_last_accessed := action_to_last_accessed.get(
                f"{service_namespace}:{action.action_name}"
            ):
                considered_unused = action.last_accessed_trackable and (
                    "LastAccessedTime" not in action_last_accessed
                    or (
                        at.timestamp()
                        - action_last_accessed["LastAccessedTime"].timestamp()
                    )
                    > seconds_since_last_accessed
                )

                last_accessed_time = action_last_accessed.get("LastAccessedTime")
                detail.granularity = "action"
                detail.action_level_last_accessed = last_accessed_time
                detail.action_level_last_authenticated_entity = (
                    action_last_accessed.get("LastAccessedEntity")
                )
                detail.action_level_last_authenticated_region = (
                    action_last_accessed.get("LastAccessedRegion")
                )
                detail.considered_unused = considered_unused
                detail.considered_unused_reason = (
                    (
                        "This action is tracked by Access Analyzer "
                        "and has not been accessed in the past "
                        f"{days_since_last_accessed} days."
                    )
                    if considered_unused is True
                    else None
                )
                detail.considered_not_unused_reason = (
                    (
                        _make_message_for_considered_not_unused_reason(
                            action.last_accessed_trackable,
                            "action",
                            days_since_last_accessed,
                        )
                    )
                    if considered_unused is False
                    else None
                )
            details.append(detail)

    return details


def _get_actions_for_policy(
    make_client: Callable[[], IAMClient],
    policy_arn: str,
    catalog_map: dict[str, dict[str, ActionTypeDef]],
) -> dict[str, list[Action]]:
    client = make_client()
    res = client.get_policy(PolicyArn=policy_arn)
    version = unwrap(res["Policy"].get("DefaultVersionId"))
    res = client.get_policy_version(PolicyArn=policy_arn, VersionId=version)
    policy_document = res["PolicyVersion"].get("Document")
    if not policy_document:
        return {}

    if isinstance(policy_document, str):
        statement = json.loads(policy_document)["Statement"]
    else:
        statement = policy_document["Statement"]

    ret: dict[str, list[Action]] = {}
    for s in statement:
        actions = s["Action"]
        if not isinstance(actions, list):
            actions = [actions]
        for action in actions:
            ns, action_name = action.split(":", 1)
            if ns not in ret:
                ret[ns] = []
            action_from_catalog = catalog_map[ns][action_name.lower()]
            ret[ns].append(
                Action(
                    service_namespace=ns,
                    action_name=action_name,
                    last_accessed_trackable=action_from_catalog[
                        "last_accessed_trackable"
                    ],
                )
            )
    return ret


def _iterate_attached_role_policies(
    make_client: Callable[[], IAMClient], role_name: str, path_prefix: str | None = None
) -> Iterable[str]:
    marker = None

    client = make_client()
    while marker is None or marker:
        kwargs = ListAttachedRolePoliciesRequestTypeDef(RoleName=role_name)
        if marker:
            kwargs["Marker"] = marker
        if path_prefix:
            kwargs["PathPrefix"] = path_prefix

        res = client.list_attached_role_policies(**kwargs)
        attached_policies = res["AttachedPolicies"]

        if attached_policies:
            yield from [unwrap(a.get("PolicyArn")) for a in attached_policies]

        marker = res.get("Marker")
        if not marker:
            break


def list_last_accessed_details(
    role_arn: str,
    catalog: Catalog,
    days_from_last_accessed: int,
    *,
    profile_name: str | None = None,
    access_key_id: str | None = None,
    secret_access_key: str | None = None,
    region: str | None = None,
) -> dict[str, list[LastAccessedDetailTypeDef]]:
    kwargs_for_session = {}
    if profile_name is not None:
        kwargs_for_session["profile_name"] = profile_name
    if access_key_id is not None:
        kwargs_for_session["aws_access_key_id"] = access_key_id
    if access_key_id is not None:
        kwargs_for_session["aws_secret_access_key"] = secret_access_key
    if region is not None:
        kwargs_for_session["region_name"] = region

    def make_client() -> IAMClient:
        session = boto3.Session(**kwargs_for_session)
        return session.client("iam")

    catalog_map = {
        service_namespace: {a["name"].lower(): a for a in actions}
        for service_namespace, actions in catalog.items()
    }

    policy_arns = list(
        _iterate_attached_role_policies(
            make_client, role_name=role_arn.rsplit("/", 1)[1]
        )
    )

    with futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as exc:
        fs = {
            policy_arn: exc.submit(
                _get_actions_for_policy, make_client, policy_arn, catalog_map
            )
            for policy_arn in policy_arns
        }

    futures.wait(fs.values())
    policy_arn_to_action_map: dict[str, dict[str, list[Action]]] = {}
    for policy_arn, f in fs.items():
        try:
            policy_arn_to_action_map[policy_arn] = f.result()
        except Exception:
            logger.exception(f"failed to gather actions for policy: {policy_arn}")

    with futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as exc:
        fs = {
            policy_arn: exc.submit(
                _get_last_accessed_details,
                make_client,
                policy_arn,
                policy_arn_to_action_map[policy_arn],
                days_from_last_accessed,
                datetime.now(),
            )
            for policy_arn in policy_arns
        }

    futures.wait(fs.values())
    policy_arn_to_last_accessed: dict[str, list[LastAccessedDetail]] = {}
    for policy_arn, f in fs.items():
        try:
            policy_arn_to_last_accessed[policy_arn] = f.result()
        except Exception:
            logger.exception(f"failed to get last accessed info: {policy_arn}")

    return {
        service_namespace: [_to_last_accessed_detail_type_def(d) for d in details]
        for service_namespace, details in policy_arn_to_last_accessed.items()
    }
