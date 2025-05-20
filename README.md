# iam-action-catalog

A CLI tool to identify IAM actions that can be safely removed — **without relying on CloudTrail or AWS Access Analyzer (external sharing)**.

This tool uses IAM's built-in *last accessed information APIs* and a local "action catalog" to determine which actions have not been used in a given time window and can be confidently considered unused.

---

## 1. Overview

This tool helps audit IAM roles, users, or groups by extracting actions that have not been used recently, **based on Access Analyzer-compatible tracking data**, but **without requiring CloudTrail logs or an Analyzer resource**.

It is designed to:
- Work without any pre-enabled AWS services
- Operate locally and safely
- Focus only on actions that can be **proven unused**

---

## 2. How It Works

The tool leverages two key data sources:
1. **IAM's last accessed data** (retrieved via `generate-service-last-accessed-details` and `get-service-last-accessed-details`)
2. **A local catalog** of IAM actions, built from public AWS documentation

Each action in the catalog includes a `last_accessed_trackable` flag, which indicates whether the action is eligible for tracking by AWS's Access Analyzer API.  
Only trackable actions are considered when evaluating usage.

---

## 3. Important Notes

This is **not** a tool for detecting *all* unused actions.  
Instead, it is designed to detect only those actions that:
- Are trackable by Access Analyzer
- Have not been accessed within a specified time window

In other words, it answers:  
> *"Which actions can I safely delete, with objective evidence that they haven't been used recently?"*

It does **not** require:
- CloudTrail
- A configured Access Analyzer resource
- Any paid AWS features

---

## 4. Installation

> ⚠️ **Requires Python 3.11 or higher**

```bash
pip install .
```

Or build and install from wheel:

```bash
pip install build
python -m build
pip install ./dist/iam_action_catalog-*.whl
```

---

## 5. Commands and Usage

### Build the catalog

```bash
iam-action-catalog --catalog-path ./catalog.json catalog build
```

This will parse AWS IAM documentation and generate a catalog of known IAM actions.

### Show catalog contents

```bash
iam-action-catalog --catalog-path ./catalog.json catalog show --pretty
```

---

### Analyze last accessed actions for a role

```bash
iam-action-catalog --catalog-path ./catalog.json \
  list-last-accessed-details \
  --arn arn:aws:iam::123456789012:role/MyRole \
  --only-considered-unused \
  --days-from-last-accessed 180 \
  --pretty
```

Options include:

* --days-from-last-accessed: Number of days of inactivity before flagging an action (default: 90)
* --output-structure list|dict: Controls output format (default: list)
* --aws-profile or --aws-access-key-id / --aws-secret-access-key: Credential injection

---

## 6. Example Output

```json
[
  {
    "arn": "arn:aws:iam::123456789012:role/MyRole",
    "items": [
      {
        "name": "arn:aws:iam::123456789012:policy/ExamplePolicy",
        "kind": "attached",
        "last_accessed_details": [
          {
            "action_name": "s3:GetObject",
            "service_name": "Amazon S3",
            "service_namespace": "s3",
            "granularity": "action_level",
            "service_level_last_authenticated": "2024-12-26T07:40:55+00:00",
            "service_level_last_authenticated_entity": "arn:aws:iam::123456789012:role/MyRole",
            "service_level_last_authenticated_region": "ap-northeast-1",
            "action_level_last_accessed": "2024-12-26T07:40:54+00:00",
            "action_level_last_authenticated_entity": "arn:aws:iam::123456789012:role/MyRole",
            "action_level_last_authenticated_region": "ap-northeast-1",
            "considered_unused": true,
            "considered_unused_reason": "This action is tracked by Access Analyzer and has not been accessed in the past 90 days.",
            "considered_not_unused_reason": null
          }
        ]
      }
    ]
  }
]
```

---

## 7. Output Format Options
The output can be formatted in two ways using the --output-structure option:

* list (default): Flat list of result objects
* dict: Top-level object mapping each analyzed ARN to its result payload

Use --pretty to enable indentation in the JSON output.

---

## 8. Explanation of `last_accessed_details` fields
Each `last_accessed_details` entry provides information about a specific IAM action found in a managed or inline policy.
These fields are used to determine whether the action is confidently considered unused.

| Field                                     | Description                                                                                            |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `action_name`                             | The name of the IAM action (e.g., `s3:GetObject`)                                                      |
| `service_name`                            | Friendly name of the AWS service (e.g., "Amazon S3")                                                   |
| `service_namespace`                       | Internal namespace of the AWS service (e.g., `s3`, `ec2`)                                              |
| `granularity`                             | Level of access tracking used: either `"service_level"` or `"action_level"`                            |
| `service_level_last_authenticated`        | Timestamp of the last access to *any* action in this service                                           |
| `service_level_last_authenticated_entity` | IAM principal that made that access                                                                    |
| `service_level_last_authenticated_region` | Region of that access                                                                                  |
| `action_level_last_accessed`              | Timestamp of the last access to this specific action (if available)                                    |
| `action_level_last_authenticated_entity`  | IAM principal that last accessed this action                                                           |
| `action_level_last_authenticated_region`  | Region where the action was last accessed                                                              |
| `considered_unused`                       | `true` if the action is trackable and not used within the threshold window                             |
| `considered_unused_reason`                | Explanation for why the action is considered unused                                                    |
| `considered_not_unused_reason`            | **Reason code** (string) indicating why the action is *not* considered unused. One of:                 |
|                                           | `"USED_WITHIN_PERIOD"` — the action was used recently                                                  |
|                                           | `"NON_TRACKABLE_ACTION"` — the action cannot be tracked by Access Analyzer                             |
|                                           | `"SERVICE_NOT_IN_RESPONSE"` — the service was not included in Access Analyzer's response               |
| `considered_not_unused_reason_detail`     | Human-readable message explaining the above reason in more detail                                      |


---

## 9. Required IAM Permissions

To run `iam-action-catalog`, the executing principal must have the following IAM permissions:

```json
[
  "iam:ListAttachedRolePolicies",
  "iam:ListRolePolicies",
  "iam:ListAttachedUserPolicies",
  "iam:ListUserPolicies",
  "iam:ListAttachedGroupPolicies",
  "iam:ListGroupPolicies",
  "iam:GenerateServiceLastAccessedDetails",
  "iam:GetServiceLastAccessedDetails",
  "iam:GetPolicy",
  "iam:GetPolicyVersion",
  "iam:GetRolePolicy",
  "iam:GetUserPolicy",
  "iam:GetGroupPolicy"
]
```

---

## License

MIT
