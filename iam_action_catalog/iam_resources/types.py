from dataclasses import dataclass


@dataclass(frozen=True)
class Action:
    service_namespace: str
    action_name: str
    last_accessed_trackable: bool
