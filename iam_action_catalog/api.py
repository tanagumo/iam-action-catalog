import time
from functools import wraps
from textwrap import dedent
from typing import Callable, ParamSpec, TypeVar, Unpack

import boto3
from botocore.exceptions import ClientError
from mypy_boto3_iam.type_defs import (
    GenerateServiceLastAccessedDetailsRequestTypeDef,
    GenerateServiceLastAccessedDetailsResponseTypeDef,
    GetGroupPolicyRequestTypeDef,
    GetGroupPolicyResponseTypeDef,
    GetPolicyRequestTypeDef,
    GetPolicyResponseTypeDef,
    GetPolicyVersionRequestTypeDef,
    GetPolicyVersionResponseTypeDef,
    GetRolePolicyRequestTypeDef,
    GetRolePolicyResponseTypeDef,
    GetServiceLastAccessedDetailsRequestTypeDef,
    GetServiceLastAccessedDetailsResponseTypeDef,
    GetUserPolicyRequestTypeDef,
    GetUserPolicyResponseTypeDef,
    ListAttachedGroupPoliciesRequestTypeDef,
    ListAttachedGroupPoliciesResponseTypeDef,
    ListAttachedRolePoliciesRequestTypeDef,
    ListAttachedRolePoliciesResponseTypeDef,
    ListAttachedUserPoliciesRequestTypeDef,
    ListAttachedUserPoliciesResponseTypeDef,
    ListGroupPoliciesRequestTypeDef,
    ListGroupPoliciesResponseTypeDef,
    ListRolePoliciesRequestTypeDef,
    ListRolePoliciesResponseTypeDef,
    ListUserPoliciesRequestTypeDef,
    ListUserPoliciesResponseTypeDef,
)

P = ParamSpec("P")
Q = TypeVar("Q")


class BotoApiError(Exception):
    def __init__(self, code: str, operation: str, message: str) -> None:
        self._operation = operation
        self._code = code
        self._message = message

    def __str__(self) -> str:
        return dedent(f"""\
                Failed to call the AWS API.
                operation: {self._operation}
                code: {self._code}
                message: {self._message}
                """)

    @classmethod
    def from_boto_client_error(cls, e: ClientError) -> "BotoApiError":
        error = e.response.get("Error", {})
        code = error.get("Code", "unknown")
        message = error.get("Message", "unknown")
        return cls(code, e.operation_name, message)

    @property
    def maybe_retryable(self) -> bool:
        return self._code in {
            "Throttling",
            "ThrottlingException",
            "RequestLimitExceeded",
            "ProvisionedThroughputExceededException",
            "ServiceUnavailable",
            "InternalError",
            "RequestTimeout",
            "RequestTimeoutException",
            "TransientFault",
        }


def _wrap_boto_api(func: Callable[P, Q]) -> Callable[P, Q]:
    @wraps(func)
    def decorated(*args: P.args, **kwargs: P.kwargs) -> Q:
        wait_secs = 1
        max_retry_count = 3

        for n in range(1, max_retry_count + 1):
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error = BotoApiError.from_boto_client_error(e)
                if n == max_retry_count or not error.maybe_retryable:
                    raise error from e

                time.sleep(wait_secs)
                wait_secs *= 2

        raise AssertionError("unreachable")

    return decorated


class IAMClient:
    def __init__(self, session: boto3.Session) -> None:
        self._client = session.client("iam")

    @_wrap_boto_api
    def list_attached_role_policies(
        self, **kwargs: Unpack[ListAttachedRolePoliciesRequestTypeDef]
    ) -> ListAttachedRolePoliciesResponseTypeDef:
        return self._client.list_attached_role_policies(**kwargs)

    @_wrap_boto_api
    def list_role_policies(
        self, **kwargs: Unpack[ListRolePoliciesRequestTypeDef]
    ) -> ListRolePoliciesResponseTypeDef:
        return self._client.list_role_policies(**kwargs)

    @_wrap_boto_api
    def list_attached_user_policies(
        self, **kwargs: Unpack[ListAttachedUserPoliciesRequestTypeDef]
    ) -> ListAttachedUserPoliciesResponseTypeDef:
        return self._client.list_attached_user_policies(**kwargs)

    @_wrap_boto_api
    def list_user_policies(
        self, **kwargs: Unpack[ListUserPoliciesRequestTypeDef]
    ) -> ListUserPoliciesResponseTypeDef:
        return self._client.list_user_policies(**kwargs)

    @_wrap_boto_api
    def list_attached_group_policies(
        self, **kwargs: Unpack[ListAttachedGroupPoliciesRequestTypeDef]
    ) -> ListAttachedGroupPoliciesResponseTypeDef:
        return self._client.list_attached_group_policies(**kwargs)

    @_wrap_boto_api
    def list_group_policies(
        self, **kwargs: Unpack[ListGroupPoliciesRequestTypeDef]
    ) -> ListGroupPoliciesResponseTypeDef:
        return self._client.list_group_policies(**kwargs)

    @_wrap_boto_api
    def generate_service_last_accessed_details(
        self, **kwargs: Unpack[GenerateServiceLastAccessedDetailsRequestTypeDef]
    ) -> GenerateServiceLastAccessedDetailsResponseTypeDef:
        return self._client.generate_service_last_accessed_details(**kwargs)

    @_wrap_boto_api
    def get_service_last_accessed_details(
        self, **kwargs: Unpack[GetServiceLastAccessedDetailsRequestTypeDef]
    ) -> GetServiceLastAccessedDetailsResponseTypeDef:
        return self._client.get_service_last_accessed_details(**kwargs)

    @_wrap_boto_api
    def get_policy(
        self, **kwargs: Unpack[GetPolicyRequestTypeDef]
    ) -> GetPolicyResponseTypeDef:
        return self._client.get_policy(**kwargs)

    @_wrap_boto_api
    def get_policy_version(
        self, **kwargs: Unpack[GetPolicyVersionRequestTypeDef]
    ) -> GetPolicyVersionResponseTypeDef:
        return self._client.get_policy_version(**kwargs)

    @_wrap_boto_api
    def get_role_policy(
        self, **kwargs: Unpack[GetRolePolicyRequestTypeDef]
    ) -> GetRolePolicyResponseTypeDef:
        return self._client.get_role_policy(**kwargs)

    @_wrap_boto_api
    def get_user_policy(
        self, **kwargs: Unpack[GetUserPolicyRequestTypeDef]
    ) -> GetUserPolicyResponseTypeDef:
        return self._client.get_user_policy(**kwargs)

    @_wrap_boto_api
    def get_group_policy(
        self, **kwargs: Unpack[GetGroupPolicyRequestTypeDef]
    ) -> GetGroupPolicyResponseTypeDef:
        return self._client.get_group_policy(**kwargs)
