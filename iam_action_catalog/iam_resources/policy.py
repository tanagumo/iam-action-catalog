import logging
import threading
from typing import Callable, Protocol, TypeAlias

from iam_action_catalog.action_catalog import Catalog
from iam_action_catalog.api import IAMClient
from iam_action_catalog.utils import mask_arn, unwrap

from .types import Action
from .utils import get_actions_from_policy_document

logger = logging.getLogger(__name__)

ServiceNamespace: TypeAlias = str
PolicyArn: TypeAlias = str
ActionName: TypeAlias = str


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

        return get_actions_from_policy_document(
            policy_document,
            lambda action: f'Skipping action "{action}" in policy "{mask_arn(self._arn)}"',
            self._catalog_map,
        )


def make_policy(
    arn: str,
    make_client: Callable[[], IAMClient],
    catalog: Catalog,
) -> PolicyProtocol:
    return Policy(arn, make_client, catalog)
