import logging
import os
import threading
from concurrent import futures
from dataclasses import dataclass, field
from enum import Enum
from typing import Final, Self, TypedDict, cast, overload
from urllib.parse import urlparse
from urllib.request import urlopen

import bs4 as bs

SCHEMA_VERSION: Final[str] = "1.0.0"

logger = logging.getLogger(__name__)


URL_PREFIX = "https://docs.aws.amazon.com/service-authorization/latest/reference/list"


class ParseError(Exception):
    @overload
    def __init__(self, tag: bs.Tag, *, child: str) -> None: ...

    @overload
    def __init__(self, tag: bs.Tag, *, attr: str) -> None: ...

    @overload
    def __init__(self, tag: bs.Tag, *, query: str) -> None: ...

    def __init__(
        self,
        tag: bs.Tag | str,
        *,
        child: str | None = None,
        attr: str | None = None,
        query: str | None = None,
    ) -> None:
        self._tag = tag
        self._child = child
        self._attr = attr
        self._query = query

    def __str__(self) -> str:
        if self._child is not None:
            return (
                f"{self._tag} is expected to have a child tag `{self._child}`, but not"
            )
        elif self._attr is not None:
            return (
                f"{self._tag} is expected to have an attribute `{self._attr}`, but not"
            )
        return f"{self._tag} is expected to have children that satisfy the query `{self._query}`"


class TagError(Exception):
    pass


def select_one_strict(tag: bs.Tag, query: str) -> bs.Tag:
    ret = tag.select_one(query)
    if ret is None:
        raise ParseError(tag, query=query)
    return ret


def get_attr_str(tag: bs.Tag, attr: str) -> str:
    value = tag.get(attr)
    if value is None:
        raise ParseError(tag, attr=attr)
    if not isinstance(value, str):
        raise TagError(f"Attribute `{attr}` of the `{tag}` must be str")
    return value


def get_tag(maybe_tag: bs.Tag, rest: str | None = None) -> bs.Tag:
    if rest is None:
        return maybe_tag

    head, *tail = rest.split(".", 1)
    if not hasattr(maybe_tag, head):
        raise ParseError(maybe_tag, attr=head)
    child = getattr(maybe_tag, head)
    if not tail:
        return child
    return get_tag(child, tail[0])


def regulate_href(ref: str) -> str:
    return f"{URL_PREFIX}{ref}" if not urlparse(ref).scheme else ref


@dataclass
class ConditionKey:
    value: str
    ref: str


@dataclass
class ResourceType:
    name: str
    ref: str
    condition_keys: list[ConditionKey] = field(default_factory=list)

    @property
    def required(self) -> bool:
        return self.name.endswith("*")

    def add_condition_keys(self, condition_keys: list[ConditionKey]):
        self.condition_keys.extend(condition_keys)


@dataclass
class ActionScenario:
    name: str
    resource_types: list[ResourceType]

    def add_resource_types(self, resource_types: list[ResourceType]):
        self.resource_types.extend(resource_types)


@dataclass
class Action:
    name: str
    ref: str | None
    last_accessed_trackable: bool
    permission_only: bool
    description: str = ""
    access_level: str = ""
    resource_types: list[ResourceType] = field(default_factory=list)
    condition_keys: list[ConditionKey] = field(default_factory=list)
    scenarios: list[ActionScenario] = field(default_factory=list)
    dependent_actions: list[str] = field(default_factory=list)

    def add_condition_keys(self, condition_keys: list[ConditionKey]):
        self.condition_keys.extend(condition_keys)

    def add_dependent_actions(self, dependent_actions: list[str]):
        self.dependent_actions.extend(dependent_actions)

    def add_scenarios(self, scenarios: list[ActionScenario]):
        self.scenarios.extend(scenarios)

    def add_resource_types(self, resource_types: list[ResourceType]):
        self.resource_types.extend(resource_types)


def make_condition_key(pair: tuple[str, str]) -> ConditionKey:
    return ConditionKey(value=pair[0], ref=pair[1])


def make_resource_types(
    mapping: dict[str, tuple[str, list[tuple[str, str]]]],
) -> list[ResourceType]:
    ret = []
    for name, (ref, pairs) in mapping.items():
        ret.append(
            ResourceType(
                name=name,
                ref=ref,
                condition_keys=[make_condition_key(pair) for pair in pairs],
            )
        )
    return ret


class ConditionKeyTypeDef(TypedDict):
    value: str
    ref: str


def _to_condition_key_type_def(ck: ConditionKey) -> ConditionKeyTypeDef:
    return {
        "value": ck.value,
        "ref": ck.ref,
    }


class ResourceTypeTypeDef(TypedDict):
    name: str
    required: bool
    ref: str
    condition_keys: list[ConditionKeyTypeDef]


def _to_resource_type_type_def(r: ResourceType) -> ResourceTypeTypeDef:
    return {
        "name": r.name[:-1] if r.required else r.name,
        "required": r.required,
        "ref": r.ref,
        "condition_keys": [_to_condition_key_type_def(ck) for ck in r.condition_keys],
    }


class ActionTypeDef(TypedDict):
    """外部APIへのレスポンスを想定したIAM Actionの構造"""

    name: str
    ref: str | None
    description: str
    access_level: str
    resource_types: list[ResourceTypeTypeDef]
    condition_keys: list[ConditionKeyTypeDef]
    dependent_actions: list[str]
    last_accessed_trackable: bool
    permission_only: bool


def _to_action_type_def(a: Action) -> ActionTypeDef:
    return {
        "name": a.name,
        "ref": a.ref,
        "description": a.description,
        "access_level": a.access_level,
        "resource_types": [_to_resource_type_type_def(r) for r in a.resource_types],
        "condition_keys": [_to_condition_key_type_def(ck) for ck in a.condition_keys],
        "dependent_actions": a.dependent_actions,
        "last_accessed_trackable": a.last_accessed_trackable,
        "permission_only": a.permission_only,
    }


def _flatten_actions(actions: list[Action]) -> list[ActionTypeDef]:
    ret: list[ActionTypeDef] = []

    for action in actions:
        ret.append(_to_action_type_def(action))
        for s in action.scenarios:
            ret.append({
                "name": f"{action.name}/{s.name}",
                "ref": action.ref,
                "description": action.description,
                "access_level": action.access_level,
                "resource_types": [
                    _to_resource_type_type_def(r) for r in s.resource_types
                ],
                # NOTE: 一つのActionに複数のSENARIOが発生するのは2025/04/29時点で
                # EC2サービスのRunInstancesアクションのみ
                # この場合condition keysは空となるようなので現状固定で空リストにしている
                "condition_keys": [],
                "dependent_actions": action.dependent_actions,
                "last_accessed_trackable": action.last_accessed_trackable,
                "permission_only": action.permission_only,
            })

    return ret


class RowKind(Enum):
    title = "title"
    """タイトル行"""
    additional = "additional"
    """複数リソースやリソースごとにCondition Keysが指定される際に発生する追加行"""
    scenario = "scenario"
    """現状EC2のRunInstancesでのみ発生するシナリオ用の行"""


def _fetch_action_table(
    url: str, last_accessed_trackable: dict[str, list[str]]
) -> tuple[str, list[ActionTypeDef]]:
    with urlopen(url) as res:
        content = res.read().decode("utf-8")
    soup = bs.BeautifulSoup(content, "html.parser")

    main_col_body = select_one_strict(soup, "div#main-col-body")
    if not (p_list := main_col_body.select("p")):
        raise ParseError(main_col_body, child="p")
    p = p_list[0]
    if "(service prefix" not in p.get_text(strip=True).lower():
        raise TagError(f"`{p}` must have service prefix")

    service_prefix = select_one_strict(p, "code").get_text(strip=True)

    last_accessed_trackable_for_service = (
        set(s) if (s := last_accessed_trackable.get(service_prefix)) else None
    )

    first_container = soup.select("div#main-col-body div.table-container")[0]

    tr_list = first_container.select("div.table-contents table:nth-of-type(1) > tr")

    actions: list[Action] = []

    for tr in tr_list:
        td_list = tr.select("td")

        # 現状EC2のRunInstancesだけ複数のSCENARIOを持つ
        # tdの要素数が5の場合にSCENARIOと判断する
        # またSCENARIOについては以下を前提としている
        # * condition_keyはResource, Actionの両方に対して指定されない
        if len(td_list) == 5:
            row_kind = RowKind.scenario
        elif len(td_list) == 3:
            row_kind = RowKind.additional
        else:
            row_kind = RowKind.title
            action_name = td_list[0].get_text(strip=True)

            a_tag = td_list[0].find("a", recursive=False)
            ref_for_action = (
                regulate_href(get_attr_str(cast(bs.Tag, a_tag), "href"))
                if a_tag
                else None
            )
            action = Action(
                name=action_name.split("[permission only]", 1)[0].strip(),
                ref=ref_for_action,
                last_accessed_trackable=(
                    action_name in last_accessed_trackable_for_service
                    if last_accessed_trackable_for_service
                    else False
                ),
                permission_only=(
                    "[permission only]" in td_list[0].get_text(strip=True).lower()
                ),
            )
            actions.append(action)

        action = actions[-1]

        match row_kind:
            case RowKind.scenario:
                scenario = ActionScenario(
                    get_tag(td_list[0], "p").get_text(strip=True), []
                )
                action.add_scenarios([scenario])
                resource_tag = td_list[2]
                p_list = resource_tag.select("p")
                resource_types = [
                    ResourceType(
                        name=get_tag(p, "a").get_text(strip=True),
                        ref=regulate_href(get_attr_str(get_tag(p, "a"), "href")),
                    )
                    for p in p_list
                ]
                scenario.add_resource_types(resource_types)
            case RowKind.title:
                description_tag = td_list[1]
                action.description = description_tag.get_text(strip=True)

                access_level_tag = td_list[2]
                action.access_level = access_level_tag.get_text(strip=True)

                resource_type = None
                resource_tag = td_list[3]
                if resource_tag.contents:
                    a_tag = get_tag(get_tag(resource_tag, "p"), "a")
                    resource_type = ResourceType(
                        name=a_tag.get_text(strip=True),
                        ref=regulate_href(get_attr_str(a_tag, "href")),
                    )
                    action.add_resource_types([resource_type])

                condition_tag = td_list[4]
                if condition_tag.contents:
                    p_list = condition_tag.select("p")
                    condition_keys = [
                        ConditionKey(
                            value=(get_tag(p, "a").get_text(strip=True)),
                            ref=regulate_href(get_attr_str(get_tag(p, "a"), "href")),
                        )
                        for p in p_list
                    ]
                    if resource_type:
                        resource_type.add_condition_keys(condition_keys)
                    else:
                        action.add_condition_keys(condition_keys)

                dependent_tag = td_list[5]
                action.add_dependent_actions([
                    p.get_text(strip=True) for p in dependent_tag.select("p")
                ])
            case RowKind.additional:
                resource_type = None
                resource_tag = td_list[0]
                if resource_tag.contents:
                    a_tag = get_tag(get_tag(resource_tag, "p"), "a")
                    resource_type = ResourceType(
                        name=a_tag.get_text(strip=True),
                        ref=regulate_href(get_attr_str(a_tag, "href")),
                    )
                    action.add_resource_types([resource_type])

                condition_tag = td_list[1]
                if condition_tag.contents:
                    p_list = condition_tag.select("p")
                    condition_keys = [
                        ConditionKey(
                            value=(get_tag(p, "a").get_text(strip=True)),
                            ref=regulate_href(
                                get_attr_str(
                                    get_tag(
                                        p,
                                        "a",
                                    ),
                                    "href",
                                )
                            ),
                        )
                        for p in p_list
                    ]
                    if resource_type:
                        resource_type.add_condition_keys(condition_keys)
                    else:
                        action.add_condition_keys(condition_keys)

                dependent_tag = td_list[2]
                action.add_dependent_actions([
                    p.get_text(strip=True) for p in dependent_tag.select("p")
                ])

    return service_prefix, _flatten_actions(actions)


def _make_last_access_trackable() -> dict[str, list[str]]:
    with urlopen(
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
        "access_policies_last-accessed-action-last-accessed.html"
        "#access_policies_last-accessed-action-last-accessed-supported-actions"
    ) as res:
        source = res.read().decode("utf-8")

    soup = bs.BeautifulSoup(source, "html.parser")

    table = soup.select("#main-col-body table")[1]
    tr_list = table.select("tr")[1:]
    service_to_last_accessed_information_actions = {}
    for tr in tr_list:
        td_list = tr.select("td")
        service_tag = td_list[0]
        service = service_tag.get_text(strip=True)
        actions_tag = td_list[1]
        actions = [
            p.get_text(strip=True).split(service, 1)[1][1:]
            for p in actions_tag.select("p")
        ]
        service_to_last_accessed_information_actions[service] = actions

    return service_to_last_accessed_information_actions


def _make_service_to_actions(
    last_accessed_trackable: dict[str, list[str]],
) -> dict[str, list[ActionTypeDef]]:
    def _make_url_from_service(service: str) -> str:
        _url_prefix = (
            "https://docs.aws.amazon.com/service-authorization/latest/reference"
        )

        mapping = {
            "AWS Management Console Mobile App": f"{_url_prefix}/list_awsconsolemobileapp.html",
            "Amazon DynamoDB Accelerator (DAX)": f"{_url_prefix}/list_amazondynamodbacceleratordax.html",
            "Amazon EMR on EKS (EMR Containers)": f"{_url_prefix}/list_amazonemroneksemrcontainers.html",
            "AWS IAM Identity Center (successor to AWS Single Sign-On)": f"{_url_prefix}/list_awsiamidentitycentersuccessortoawssinglesign-on.html",
            "AWS IAM Identity Center (successor to AWS Single Sign-On) directory": f"{_url_prefix}/list_awsiamidentitycentersuccessortoawssinglesign-ondirectory.html",
            "AWS Identity and Access Management (IAM)": f"{_url_prefix}/list_awsidentityandaccessmanagementiam.html",
            # the page for this service does not describe actions
            "AWS IoT 1-Click": "",
            "Amazon Keyspaces (for Apache Cassandra)": f"{_url_prefix}/list_amazonkeyspacesforapachecassandra.html",
            "AWS Resource Access Manager (RAM)": f"{_url_prefix}/list_awsresourceaccessmanagerram.html",
        }

        if service in mapping:
            return mapping[service]

        return f"{URL_PREFIX}_{''.join([i.lower() for i in service.split(' ')])}.html"

    with urlopen(
        "https://docs.aws.amazon.com/service-authorization/latest/reference/"
        "reference_policies_actions-resources-contextkeys.html"
    ) as res:
        source = res.read().decode("utf-8")

    soup = bs.BeautifulSoup(source, "html.parser")
    ul = select_one_strict(soup, "#main-col-body div.highlights > ul")
    services = [
        get_tag(get_tag(cast(bs.Tag, li), "p")).get_text(strip=True)
        for li in ul.find_all("li")
    ]
    urls = [url for url in [_make_url_from_service(s) for s in services] if url]

    service_to_actions = {}
    with futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as executor:
        url_to_future = {
            url: executor.submit(_fetch_action_table, url, last_accessed_trackable)
            for url in urls
        }

        for url, f in url_to_future.items():
            try:
                service_prefix, actions = f.result()
                service_to_actions[service_prefix] = actions
            except Exception:
                logger.exception(f"failed to parse. url: {url}")

    return service_to_actions


class GlobalServiceToActions:
    _instance: Self | None = None
    _lock: threading.Lock = threading.Lock()

    def __init__(
        self,
        _service_to_actions: dict[str, list[ActionTypeDef]],
        _internal: bool = False,
    ) -> None:
        if not _internal:
            raise RuntimeError("cannot instantiate")
        self._service_to_actions = _service_to_actions

    @classmethod
    def instance(cls) -> Self:
        with cls._lock:
            if cls._instance is None:
                last_accessed_trackable = _make_last_access_trackable()
                cls._instance = cls(
                    _make_service_to_actions(last_accessed_trackable),
                    _internal=True,
                )
            return cls._instance

    def value(self) -> dict[str, list[ActionTypeDef]]:
        return self._service_to_actions
