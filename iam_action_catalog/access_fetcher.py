import logging
import os
import threading
import time
from concurrent import futures
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import (
    Callable,
    Literal,
    TypeAlias,
    TypedDict,
)

import boto3
from mypy_boto3_iam.type_defs import (
    GetServiceLastAccessedDetailsRequestTypeDef,
    ServiceLastAccessedTypeDef,
    TrackedActionLastAccessedTypeDef,
)

from iam_action_catalog.action_catalog import Catalog
from iam_action_catalog.api import IAMClient
from iam_action_catalog.iam_resources import (
    Action,
    Arn,
    PolicyHolderProtocol,
    make_policy_holder,
)
from iam_action_catalog.utils import mask_arn, unwrap

logger = logging.getLogger(__name__)


class GetLastAccessedDetailError(Exception):
    def __init__(
        self,
        arn: str,
        error_code: str,
        error_message: str,
    ) -> None:
        self.arn = arn
        self.error_code = error_code
        self.error_message = error_message
        super().__init__(self._to_str())

    def _to_str(self) -> str:
        return (
            f"GetLastAccessedDetailError(arn={mask_arn(self.arn)}, "
            f"error_code={self.error_code}, "
            f"error_message={self.error_message})"
        )

    def __str__(self) -> str:
        return self._to_str()


class NotUnusedReason(Enum):
    NON_TRACKABLE_ACTION = "non_trackable_action"
    USED_WITHIN_PERIOD = "used_within_period"
    SERVICE_NOT_IN_RESPONSE = "service_not_in_response"

    def make_detail_message(self, days: int) -> str:
        match self:
            case NotUnusedReason.NON_TRACKABLE_ACTION:
                return "Not considered unused because the action is not trackable by Access Analyzer."
            case NotUnusedReason.USED_WITHIN_PERIOD:
                return f"Not considered unused because it was used within {days} days."
            case NotUnusedReason.SERVICE_NOT_IN_RESPONSE:
                return "Service was not included in get_service_last_accessed_details response. Possibly not trackable."


@dataclass
class LastAccessedDetail:
    action_name: str
    service_namespace: str
    service_name: str | None
    granularity: Literal["service", "action"] | None
    service_level_last_authenticated: datetime | None
    service_level_last_authenticated_entity: str | None
    service_level_last_authenticated_region: str | None
    action_level_last_accessed: datetime | None
    action_level_last_authenticated_entity: str | None
    action_level_last_authenticated_region: str | None
    considered_unused: bool
    considered_unused_reason: str | None
    considered_not_unused_reason: NotUnusedReason | None


class LastAccessedDetailTypeDef(TypedDict):
    action_name: str
    service_namespace: str
    service_name: str | None
    granularity: Literal["service_level", "action_level"] | None
    service_level_last_authenticated: str | None
    service_level_last_authenticated_entity: str | None
    service_level_last_authenticated_region: str | None
    action_level_last_accessed: str | None
    action_level_last_authenticated_entity: str | None
    action_level_last_authenticated_region: str | None
    considered_unused: bool
    considered_unused_reason: str | None
    considered_not_unused_reason: str | None
    considered_not_unused_reason_detail: str | None


def _to_last_accessed_detail_type_def(
    detail: LastAccessedDetail, days_from_last_accessed: int
) -> LastAccessedDetailTypeDef:
    considered_not_unused_reason = detail.considered_not_unused_reason

    return LastAccessedDetailTypeDef(
        action_name=detail.action_name,
        service_namespace=detail.service_namespace,
        service_name=detail.service_name,
        granularity="service_level"
        if detail.granularity == "service"
        else "action_level"
        if detail.granularity == "action"
        else None,
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
        considered_not_unused_reason=str(considered_not_unused_reason.value)
        if considered_not_unused_reason
        else None,
        considered_not_unused_reason_detail=considered_not_unused_reason.make_detail_message(
            days_from_last_accessed
        )
        if considered_not_unused_reason
        else None,
    )


PolicyKind: TypeAlias = Literal["attached", "inline"]


class LastAccessFetchResultItemTypeDef(TypedDict):
    name: str
    kind: PolicyKind
    last_accessed_details: list[LastAccessedDetailTypeDef]


class LastAccessFetchResultTypeDef(TypedDict):
    arn: str
    items: list[LastAccessFetchResultItemTypeDef]


class LastAccessFetcher:
    _lock: threading.Lock = threading.Lock()

    @dataclass
    class _IntermediateResult:
        service_to_last_accessed: dict[str, ServiceLastAccessedTypeDef]
        action_to_last_accessed: dict[str, TrackedActionLastAccessedTypeDef]

    def __init__(
        self,
        make_client: Callable[[], IAMClient],
        catalog: Catalog,
    ) -> None:
        self._make_client = make_client
        self._catalog_map = {
            service_namespace.lower(): {a["name"].lower(): a for a in actions}
            for service_namespace, actions in catalog.items()
        }

    @dataclass(frozen=True)
    class _Policy:
        kind: PolicyKind
        name: str

    def _ensure_client(self) -> IAMClient:
        with self._lock:
            client = getattr(self, "__client", None)
            if client is None:
                client = self._make_client()
                setattr(self, "__client", client)
            return client

    def fetch(
        self,
        policy_holders: list[PolicyHolderProtocol],
        days_from_last_accessed: int,
        only_considered_unused: bool,
    ) -> list[LastAccessFetchResultTypeDef]:
        with futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as exc:
            fs = {
                ph.arn: exc.submit(
                    self._get_details_for_policy_holder, ph, days_from_last_accessed
                )
                for ph in policy_holders
            }

        arn_to_last_accessed_details_result: dict[
            Arn,
            list[tuple[LastAccessFetcher._Policy, list[LastAccessedDetail]]],
        ] = {}
        for arn, f in fs.items():
            try:
                arn_to_last_accessed_details_result[arn] = f.result()
            except Exception as e:
                logger.error(
                    f"Failed to fetch last accessed detail for {mask_arn(arn)}"
                )
                logger.error(str(e))

        arns = [ph.arn for ph in policy_holders]
        return [
            LastAccessFetchResultTypeDef(
                arn=mask_arn(arn),
                items=[
                    LastAccessFetchResultItemTypeDef(
                        name=mask_arn(item[0].name),
                        kind=item[0].kind,
                        last_accessed_details=[
                            _to_last_accessed_detail_type_def(
                                i, days_from_last_accessed
                            )
                            for i in sorted(
                                item[1],
                                key=lambda d: (d.service_namespace, d.action_name),
                            )
                            if not only_considered_unused
                            or _to_last_accessed_detail_type_def(
                                i, days_from_last_accessed
                            )["considered_unused"]
                        ],
                    )
                    for item in sorted(
                        arn_to_last_accessed_details_result[arn],
                        key=lambda item: (item[0].kind, item[0].name),
                    )
                ],
            )
            for arn in arns
        ]

    def _get_intermediate_result(
        self, arn: str
    ) -> "LastAccessFetcher._IntermediateResult":
        client = self._ensure_client()
        res = client.generate_service_last_accessed_details(
            Arn=arn, Granularity="ACTION_LEVEL"
        )

        job_id = res["JobId"]

        marker = None
        service_to_last_accessed: dict[str, ServiceLastAccessedTypeDef] = {}
        action_to_last_accessed: dict[str, TrackedActionLastAccessedTypeDef] = {}

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
                error = res.get("Error", {})
                raise GetLastAccessedDetailError(
                    arn,
                    error_code=error.get("Code", "unkown"),
                    error_message=error.get("Message", "unkown"),
                )
            if res["JobStatus"] == "IN_PROGRESS":
                time.sleep(1)

        return self._IntermediateResult(
            service_to_last_accessed, action_to_last_accessed
        )

    def _get_intermediate_result_for_policy_holder(
        self, policy_holder: PolicyHolderProtocol
    ) -> "LastAccessFetcher._IntermediateResult":
        return self._get_intermediate_result(policy_holder.arn)

    def _get_details_for_policy_holder(
        self, policy_holder: PolicyHolderProtocol, days_from_last_accessed: int
    ) -> list[tuple[_Policy, list[LastAccessedDetail]]]:
        Policy = self._Policy

        details_map: dict[LastAccessFetcher._Policy, list[LastAccessedDetail]] = {}
        intermediate_result = self._get_intermediate_result_for_policy_holder(
            policy_holder
        )
        action_to_detail: dict[str, LastAccessedDetail] = {}

        keys: set[LastAccessFetcher._Policy] = set()
        now = datetime.now()

        for (
            policy_arn,
            actions,
        ) in policy_holder.get_actions_for_attached_policies().items():
            for action in actions:
                key = f"{action.service_namespace}:{action.action_name}"
                if key not in action_to_detail:
                    detail = self._to_last_accessed_details(
                        intermediate_result,
                        action,
                        days_from_last_accessed,
                        now,
                    )
                    action_to_detail[key] = detail

                policy = Policy("attached", mask_arn(policy_arn))
                if policy not in details_map:
                    details_map[policy] = []
                details_map[policy].append(action_to_detail[key])
                keys.add(policy)

        for (
            policy_name,
            actions,
        ) in policy_holder.get_actions_for_inline_policies().items():
            for action in actions:
                key = f"{action.service_namespace}:{action.action_name}"
                if key not in action_to_detail:
                    detail = self._to_last_accessed_details(
                        intermediate_result,
                        action,
                        days_from_last_accessed,
                        now,
                    )
                    action_to_detail[key] = detail

                policy = Policy("inline", policy_name)
                if policy not in details_map:
                    details_map[policy] = []
                details_map[policy].append(action_to_detail[key])
                keys.add(policy)

        return [
            (key, details_map[key])
            for key in sorted(keys, key=lambda p: (p.kind, p.name))
        ]

    def _to_last_accessed_details(
        self,
        result: "LastAccessFetcher._IntermediateResult",
        action: Action,
        days_from_last_accessed: int,
        at: datetime,
    ) -> LastAccessedDetail:
        if action.service_namespace not in result.service_to_last_accessed:
            return LastAccessedDetail(
                action_name=action.action_name,
                service_namespace=action.service_namespace,
                service_name=None,
                service_level_last_authenticated=None,
                granularity=None,
                service_level_last_authenticated_entity=None,
                service_level_last_authenticated_region=None,
                action_level_last_accessed=None,
                action_level_last_authenticated_entity=None,
                action_level_last_authenticated_region=None,
                considered_unused=False,
                considered_unused_reason=None,
                considered_not_unused_reason=NotUnusedReason.SERVICE_NOT_IN_RESPONSE,
            )

        seconds_since_last_accessed = days_from_last_accessed * 86400

        service_namespace = action.service_namespace
        service_last_accessed = result.service_to_last_accessed[service_namespace]

        considered_unused = action.last_accessed_trackable and (
            "LastAuthenticated" not in service_last_accessed
            or (at.timestamp() - service_last_accessed["LastAuthenticated"].timestamp())
            > seconds_since_last_accessed
        )

        if not considered_unused:
            if not action.last_accessed_trackable:
                considered_not_unused_reason = NotUnusedReason.NON_TRACKABLE_ACTION
            else:
                considered_not_unused_reason = NotUnusedReason.USED_WITHIN_PERIOD
        else:
            considered_not_unused_reason = None

        detail = LastAccessedDetail(
            action_name=action.action_name,
            service_name=service_last_accessed["ServiceName"],
            service_namespace=service_last_accessed["ServiceNamespace"],
            service_level_last_authenticated=service_last_accessed.get(
                "LastAuthenticated"
            ),
            granularity="service",
            service_level_last_authenticated_entity=mask_arn(
                service_last_accessed.get("LastAuthenticatedEntity")
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
                f"{days_from_last_accessed} days."
            )
            if considered_unused is True
            else None,
            considered_not_unused_reason=considered_not_unused_reason,
        )

        if action_last_accessed := result.action_to_last_accessed.get(
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

            if not considered_unused:
                if not action.last_accessed_trackable:
                    considered_not_unused_reason = NotUnusedReason.NON_TRACKABLE_ACTION
                else:
                    considered_not_unused_reason = NotUnusedReason.USED_WITHIN_PERIOD
            else:
                considered_not_unused_reason = None

            last_accessed_time = action_last_accessed.get("LastAccessedTime")
            detail.granularity = "action"
            detail.action_level_last_accessed = last_accessed_time
            detail.action_level_last_authenticated_entity = mask_arn(
                action_last_accessed.get("LastAccessedEntity")
            )
            detail.action_level_last_authenticated_region = action_last_accessed.get(
                "LastAccessedRegion"
            )
            detail.considered_unused = considered_unused
            detail.considered_unused_reason = (
                (
                    "This action is tracked by Access Analyzer "
                    "and has not been accessed in the past "
                    f"{days_from_last_accessed} days."
                )
                if considered_unused is True
                else None
            )
            detail.considered_not_unused_reason = considered_not_unused_reason
        return detail


def list_last_accessed_details(
    *,
    arn: str,
    catalog: Catalog,
    days_from_last_accessed: int,
    only_considered_unused: bool,
    profile_name: str | None = None,
    access_key_id: str | None = None,
    secret_access_key: str | None = None,
    region: str | None = None,
) -> list[LastAccessFetchResultTypeDef]:
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
        return IAMClient(session)

    policy_holder = make_policy_holder(arn, make_client, catalog)
    fetcher = LastAccessFetcher(make_client, catalog)
    return fetcher.fetch(
        days_from_last_accessed, only_considered_unused, policy_holders=[policy_holder]
    )
