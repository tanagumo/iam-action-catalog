import logging
import os
import re
import threading
from concurrent import futures
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Generator,
    Generic,
    Mapping,
    Protocol,
    TypeAlias,
    TypedDict,
    TypeVar,
)

from mypy_boto3_iam.type_defs import (
    ListAttachedGroupPoliciesRequestTypeDef,
    ListAttachedRolePoliciesRequestTypeDef,
    ListAttachedUserPoliciesRequestTypeDef,
    ListGroupPoliciesRequestTypeDef,
    ListRolePoliciesRequestTypeDef,
    ListUserPoliciesRequestTypeDef,
    PolicyDocumentTypeDef,
)

from iam_action_catalog.action_catalog import Catalog
from iam_action_catalog.api import IAMClient
from iam_action_catalog.utils import mask_arn, unwrap

from .types import Action
from .utils import get_actions_from_policy_document

ServiceNamespace: TypeAlias = str
PolicyArn: TypeAlias = str
PolicyName: TypeAlias = str
Arn: TypeAlias = str
ActionName: TypeAlias = str

logger = logging.getLogger(__name__)


Req = TypeVar("Req", bound=Mapping)
Item = TypeVar("Item")


class ListApi(Generic[Req, Item]):
    def __init__(self, client: IAMClient) -> None:
        self._client = client

    def _call(self, req: dict[str, Any]) -> tuple[list[Item], str | None]:
        raise NotImplementedError

    def call(self, req: Req) -> Generator[Item, None, None]:
        marker = None

        while marker is None or marker:
            kwargs = dict(**req)
            if marker:
                kwargs.update({"Marker": marker})

            items, next_marker = self._call(kwargs)

            if items:
                yield from items

            marker = next_marker
            if not marker:
                return


@dataclass(frozen=True)
class AttachedPolicy:
    arn: str
    name: str


class ListIamRoleAttachedPoliciesApi(
    ListApi[ListAttachedRolePoliciesRequestTypeDef, AttachedPolicy]
):
    def _call(self, req: dict[str, Any]) -> tuple[list[AttachedPolicy], str | None]:
        res = self._client.list_attached_role_policies(**req)
        items = [
            AttachedPolicy(
                arn=unwrap(p.get("PolicyArn")), name=unwrap(p.get("PolicyName"))
            )
            for p in res["AttachedPolicies"]
        ]
        marker = res.get("Marker")
        return (items, marker)


class ListIamRolePoliciesApi(ListApi[ListRolePoliciesRequestTypeDef, str]):
    def _call(self, req: dict[str, Any]) -> tuple[list[str], str | None]:
        res = self._client.list_role_policies(**req)
        items = [name for name in res["PolicyNames"]]
        marker = res.get("Marker")
        return (items, marker)


class ListIamGroupAttachedPoliciesApi(
    ListApi[ListAttachedGroupPoliciesRequestTypeDef, AttachedPolicy]
):
    def _call(self, req: dict[str, Any]) -> tuple[list[AttachedPolicy], str | None]:
        res = self._client.list_attached_group_policies(**req)
        items = [
            AttachedPolicy(
                arn=unwrap(p.get("PolicyArn")), name=unwrap(p.get("PolicyName"))
            )
            for p in res["AttachedPolicies"]
        ]
        marker = res.get("Marker")
        return (items, marker)


class ListIamGroupPoliciesApi(ListApi[ListGroupPoliciesRequestTypeDef, str]):
    def _call(self, req: dict[str, Any]) -> tuple[list[str], str | None]:
        res = self._client.list_group_policies(**req)
        items = [name for name in res["PolicyNames"]]
        marker = res.get("Marker")
        return (items, marker)


class ListIamUserAttachedPoliciesApi(
    ListApi[ListAttachedUserPoliciesRequestTypeDef, AttachedPolicy]
):
    def _call(self, req: dict[str, Any]) -> tuple[list[AttachedPolicy], str | None]:
        res = self._client.list_attached_user_policies(**req)
        items = [
            AttachedPolicy(
                arn=unwrap(p.get("PolicyArn")), name=unwrap(p.get("PolicyName"))
            )
            for p in res["AttachedPolicies"]
        ]
        marker = res.get("Marker")
        return (items, marker)


class ListIamUserPoliciesApi(ListApi[ListUserPoliciesRequestTypeDef, str]):
    def _call(self, req: dict[str, Any]) -> tuple[list[str], str | None]:
        res = self._client.list_user_policies(**req)
        items = [name for name in res["PolicyNames"]]
        marker = res.get("Marker")
        return (items, marker)


class InlinePolicyTypeDef(TypedDict):
    policy_name: str
    policy_document: PolicyDocumentTypeDef


class PolicyHolderProtocol(Protocol):
    @property
    def arn(self) -> str: ...

    def get_actions_for_attached_policies(
        self,
    ) -> dict[PolicyArn, set[Action]]: ...

    def get_actions_for_inline_policies(
        self,
    ) -> dict[PolicyName, set[Action]]: ...


class PolicyHolder(PolicyHolderProtocol):
    _lock: threading.Lock = threading.Lock()

    def __init__(
        self,
        arn: str,
        make_client: Callable[[], IAMClient],
        catalog: Catalog,
    ) -> None:
        self._arn = arn
        self._make_client = make_client
        self._catalog_map = {
            service_namespace.lower(): {a["name"].lower(): a for a in actions}
            for service_namespace, actions in catalog.items()
        }

    @property
    def arn(self) -> str:
        return self._arn

    def _ensure_client(self) -> IAMClient:
        with self._lock:
            client = getattr(self, "__client", None)
            if client is None:
                client = self._make_client()
                setattr(self, "__client", client)
            return client

    def _get_actions_for_policy(self, policy_arn: str) -> set[Action]:
        client = self._ensure_client()

        res = client.get_policy(PolicyArn=policy_arn)
        version = unwrap(res["Policy"].get("DefaultVersionId"))
        res = client.get_policy_version(PolicyArn=policy_arn, VersionId=version)
        policy_document = res["PolicyVersion"].get("Document")
        if not policy_document:
            return set()

        return get_actions_from_policy_document(
            policy_document,
            lambda action: f'Skipping action "{action}" in policy "{mask_arn(policy_arn)}"',
            self._catalog_map,
        )

    def _get_actions_for_inline_policy(self, policy_name: str) -> set[Action]:
        inline_policy = self._get_inline_policy(policy_name)
        policy_document = inline_policy["policy_document"]
        if not policy_document:
            return set()

        return get_actions_from_policy_document(
            policy_document,
            lambda action: f'Skipping action "{action}" in policy "{mask_arn(self._arn)}/{policy_name}"',
            self._catalog_map,
        )

    def get_actions_for_attached_policies(
        self,
    ) -> dict[PolicyArn, set[Action]]:
        policy_arns = self._list_attached_policy_arns()

        with futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as exc:
            fs = {
                policy_arn: exc.submit(self._get_actions_for_policy, policy_arn)
                for policy_arn in policy_arns
            }

            policy_to_actions = {}
            for policy_arn, f in fs.items():
                try:
                    policy_to_actions[policy_arn] = f.result()
                except Exception:
                    logger.exception(
                        f"failed to gather actions for policy: {mask_arn(policy_arn)}"
                    )
        return policy_to_actions

    def get_actions_for_inline_policies(
        self,
    ) -> dict[PolicyName, set[Action]]:
        policy_names = self._list_inline_policy_names()

        with futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as exc:
            fs = {
                policy_name: exc.submit(
                    self._get_actions_for_inline_policy, policy_name
                )
                for policy_name in policy_names
            }

            name_to_actions = {}
            for policy_name, f in fs.items():
                try:
                    name_to_actions[policy_name] = f.result()
                except Exception:
                    logger.exception(
                        f"failed to gather actions for inline policy: {policy_name}"
                    )
        return name_to_actions

    def _list_attached_policy_arns(self) -> list[str]:
        raise NotImplementedError

    def _list_inline_policy_names(self) -> list[str]:
        raise NotImplementedError

    def _get_inline_policy(self, policy_name: str) -> InlinePolicyTypeDef:
        raise NotImplementedError


class IamRole(PolicyHolder):
    @property
    def role_name(self) -> str:
        return self._arn.rsplit("/", 1)[1]

    def _list_attached_policy_arns(self) -> list[str]:
        api = ListIamRoleAttachedPoliciesApi(self._ensure_client())
        return [p.arn for p in api.call({"RoleName": self.role_name})]

    def _list_inline_policy_names(self) -> list[str]:
        api = ListIamRolePoliciesApi(self._ensure_client())
        return [name for name in api.call({"RoleName": self.role_name})]

    def _get_inline_policy(self, policy_name: str) -> InlinePolicyTypeDef:
        res = self._ensure_client().get_role_policy(
            RoleName=self.role_name,
            PolicyName=policy_name,
        )
        return InlinePolicyTypeDef(
            policy_name=policy_name, policy_document=res["PolicyDocument"]
        )


class IamGroup(PolicyHolder):
    @property
    def group_name(self) -> str:
        return self._arn.rsplit("/", 1)[1]

    def _list_attached_policy_arns(self) -> list[str]:
        api = ListIamGroupAttachedPoliciesApi(self._ensure_client())
        return [p.arn for p in api.call({"GroupName": self.group_name})]

    def _list_inline_policy_names(self) -> list[str]:
        api = ListIamGroupPoliciesApi(self._ensure_client())
        return [name for name in api.call({"GroupName": self.group_name})]

    def _get_inline_policy(self, policy_name: str) -> InlinePolicyTypeDef:
        res = self._ensure_client().get_group_policy(
            GroupName=self.group_name,
            PolicyName=policy_name,
        )
        return InlinePolicyTypeDef(
            policy_name=policy_name, policy_document=res["PolicyDocument"]
        )


class IamUser(PolicyHolder):
    @property
    def user_name(self) -> str:
        return self._arn.rsplit("/", 1)[1]

    def _list_attached_policy_arns(self) -> list[str]:
        api = ListIamUserAttachedPoliciesApi(self._ensure_client())
        return [p.arn for p in api.call({"UserName": self.user_name})]

    def _list_inline_policy_names(self) -> list[str]:
        api = ListIamUserPoliciesApi(self._ensure_client())
        return [name for name in api.call({"UserName": self.user_name})]

    def _get_inline_policy(self, policy_name: str) -> InlinePolicyTypeDef:
        res = self._ensure_client().get_user_policy(
            UserName=self.user_name,
            PolicyName=policy_name,
        )
        return InlinePolicyTypeDef(
            policy_name=policy_name, policy_document=res["PolicyDocument"]
        )


_role_arn_pat = re.compile(r"^arn:aws:iam::\d{12}:role/.+$")
_group_arn_pat = re.compile(r"^arn:aws:iam::\d{12}:group/.+$")
_user_arn_pat = re.compile(r"^arn:aws:iam::\d{12}:user/.+$")


def make_policy_holder(
    arn: str,
    make_client: Callable[[], IAMClient],
    catalog: Catalog,
) -> PolicyHolderProtocol:
    if _role_arn_pat.search(arn):
        return IamRole(arn, make_client, catalog)
    if _group_arn_pat.search(arn):
        return IamGroup(arn, make_client, catalog)
    if _user_arn_pat.search(arn):
        return IamUser(arn, make_client, catalog)

    raise AssertionError()
