# iam-action-catalog

`iam-action-catalog` is a CLI tool that scrapes the official AWS IAM documentation to extract a list of IAM actions per service, including the `last_accessed_trackable` flag — which indicates whether each action is tracked by AWS Access Analyzer for unused permission analysis.

The tool automatically caches results to avoid redundant scraping and will transparently re-fetch the latest data if the cache is missing, expired, or malformed.

> ✅ Ideal for detecting unused IAM permissions **even without CloudTrail**, by leveraging `last_accessed_trackable`.

---

## Features

- 🧩 **Scrapes IAM actions per AWS service**
- 🔍 **Extracts `last_accessed_trackable`**, used in Access Analyzer to determine unused permissions
- 📦 **Caches results**, and auto-rebuilds if:
  - The cache file does not exist
  - The cache is broken or malformed
  - The cache is older than 1 day (by default)
- 📤 Outputs structured JSON (optionally pretty-printed)

---

## Installation

> ⚠️ **Requires Python 3.10 or higher**

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

## Usage

```bash
iam-action-catalog --cache-path ./out.json
```

### Options

| Option               | Description                                    |
|----------------------|------------------------------------------------|
| `--cache-path`       | Path to the cache file (required)              |
| `--rebuild-cache`    | Forces a fresh scrape, ignoring any cache      |
| `--pretty`           | Pretty-print the resulting JSON to stdout      |

### Example

```bash
iam-action-catalog --cache-path ./iam_actions.json --pretty
```

---

## Output Format

The output is a JSON object structured as follows:

```json
{
  "meta": {
    "schema_version": "1.0.0",
    "generated_timestamp": 1715490060
  },
  "actions": {
    "s3": [
      {
        "name": "ListBucket",
        "ref": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html",
        "description": "Grants permission to list some or all of the objects in an Amazon S3 bucket (up to 1000)",
        "access_level": "List",
        "resource_types": [
          {
            "name": "bucket",
            "required": true,
            "ref": "https://docs.aws.amazon.com/service-authorization/latest/reference/list#amazons3-bucket",
            "condition_keys": []
          }
        ],
        "condition_keys": [
          {
            "value": "s3:AccessGrantsInstanceArn",
            "ref": "https://docs.aws.amazon.com/service-authorization/latest/reference/list#amazons3-s3_AccessGrantsInstanceArn"
          },
          ...
        ],
        "dependent_actions": [],
        "last_accessed_trackable": false,
        "permission_only": false
      },
      {
        "name": "DeleteBucket",
        "ref": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html",
        "description": "Grants permission to delete the bucket named in the URI",
        "access_level": "Write",
        "resource_types": [
          {
            "name": "bucket",
            "required": true,
            "ref": "https://docs.aws.amazon.com/service-authorization/latest/reference/list#amazons3-bucket",
            "condition_keys": []
          }
        ],
        "condition_keys": [
          {
            "value": "s3:authType",
            "ref": "https://docs.aws.amazon.com/service-authorization/latest/reference/list#amazons3-s3_authType"
          },
          ...
        ],
        "dependent_actions": [],
        "last_accessed_trackable": true,
        "permission_only": false
      },
      ...
    ],
    ...
  }
}
```

- `meta.schema_version`: Format version of the cache.
- `meta.generated_timestamp`: Unix timestamp (UTC) indicating when the data was scraped.
- `last_accessed_trackable`: Whether this action is included in Access Analyzer tracking.

---

## What is `last_accessed_trackable`?

This flag indicates whether an IAM action is included in AWS's **Access Analyzer unused actions report**.

Actions **not marked as `last_accessed_trackable` will never appear in those reports**, even if unused.

By extracting this metadata directly from AWS documentation, this tool enables **more accurate IAM permission cleanup** — even in environments without CloudTrail.

---

## Development

### Run from source

```bash
python -m iam_action_catalog --cache-path ./out.json
```

### Formatting & Linting

```bash
pip install -r requirements-dev.txt
```

---

## ⚠️ Limitations

This tool depends on scraping HTML pages from the official AWS IAM documentation.

Because AWS does **not provide a structured API or schema for IAM actions**, the tool relies on **undocumented and unofficial DOM structure**, which is subject to change.

If AWS changes the page layout or internal structure:

- This tool **may break**
- It will emit a warning and attempt to rebuild the cache
- You may need to update the scraper logic

If you notice incorrect or missing data, check the [IAM actions documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html) for changes.

---

## License

MIT

---

## 📝 TODO

Planned features include:

- `--service <service>`: Output actions for a specific AWS service only
- `--only-trackable`: Output only actions where `last_accessed_trackable == true`
- `--access-log <file> --min-unused-days <int>`:
  Cross-reference with Access Analyzer results and output actions that:
  - Are `last_accessed_trackable == true`, and
  - Have not been used for at least the specified number of days
