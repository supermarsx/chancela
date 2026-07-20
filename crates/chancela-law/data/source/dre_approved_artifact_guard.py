#!/usr/bin/env python3
"""Dry-run guard for approved rendered DRE artifacts.

This operator check is intentionally read-only. It verifies that a supplied
rendered DRE artifact is already represented by an approved capture-manifest
row, that the artifact bytes match the pinned sha256, and that the row's
article coverage maps to known Pending corpus articles. It then prints the
articles that a later, separate vendoring step would be allowed to promote.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MANIFEST = os.path.join(HERE, "dre-captures.manifest.json")
DEFAULT_CORPUS = os.path.join(HERE, "..", "law_corpus.json")
LEGAL_APPROVAL_MARKER = "LEGAL_APPROVED_FOR_VERIFIED"


class GuardError(Exception):
    pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _is_lower_sha256(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _is_rfc3339_utc(value) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return value.endswith("Z") or value.endswith("+00:00")


def _manifest_artifact_abs(manifest_path: str, captured_artifact_path: str) -> str:
    parts = captured_artifact_path.replace("\\", "/").split("/")
    if os.path.isabs(captured_artifact_path) or ".." in parts:
        raise GuardError("captured_artifact_path must be a safe path relative to the manifest directory")
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(manifest_path)), captured_artifact_path))


def _load_manifest(path: str) -> dict:
    manifest = _load_json(path)
    if manifest.get("schema_version") != 1:
        raise GuardError("manifest schema_version must be 1")
    if manifest.get("approval_marker_required") != LEGAL_APPROVAL_MARKER:
        raise GuardError(f"manifest approval_marker_required must be {LEGAL_APPROVAL_MARKER}")
    if not isinstance(manifest.get("captures"), list):
        raise GuardError("manifest captures must be an array")
    return manifest


def _find_capture(manifest: dict, manifest_path: str, artifact_path: str, diploma_id: str | None) -> dict:
    artifact_abs = os.path.abspath(artifact_path)
    matches = []
    for capture in manifest["captures"]:
        if diploma_id is not None and capture.get("diploma_id") != diploma_id:
            continue
        captured_path = capture.get("captured_artifact_path")
        if not isinstance(captured_path, str) or not captured_path.strip():
            continue
        try:
            candidate_abs = _manifest_artifact_abs(manifest_path, captured_path)
        except GuardError:
            if diploma_id is not None and capture.get("diploma_id") == diploma_id:
                raise
            continue
        if os.path.normcase(candidate_abs) == os.path.normcase(artifact_abs):
            matches.append(capture)

    if not matches:
        hint = f" for diploma {diploma_id}" if diploma_id else ""
        raise GuardError(f"no manifest-approved artifact row matches {artifact_abs}{hint}")
    if len(matches) > 1:
        raise GuardError(f"artifact path is ambiguous in manifest: {artifact_abs}")
    return matches[0]


def _validate_approved_capture(capture: dict, artifact_path: str, actual_sha256: str) -> None:
    diploma_id = capture.get("diploma_id", "<missing>")
    if capture.get("reviewer_status") != "Approved":
        raise GuardError(f"{diploma_id} reviewer_status is not Approved")
    if capture.get("legal_approval_status") != "Approved":
        raise GuardError(f"{diploma_id} legal_approval_status is not Approved")
    if capture.get("approval_marker") != LEGAL_APPROVAL_MARKER:
        raise GuardError(f"{diploma_id} approval_marker must be {LEGAL_APPROVAL_MARKER}")
    if not _is_rfc3339_utc(capture.get("capture_timestamp")):
        raise GuardError(f"{diploma_id} capture_timestamp must be RFC3339 UTC")
    if not _is_lower_sha256(capture.get("sha256")):
        raise GuardError(f"{diploma_id} sha256 must be lowercase sha256 hex")
    if capture["sha256"] != actual_sha256:
        raise GuardError(
            f"{diploma_id} artifact sha256 mismatch: expected {capture['sha256']} got {actual_sha256}"
        )
    if not os.path.isfile(artifact_path):
        raise GuardError(f"artifact does not exist: {artifact_path}")
    article_ids = capture.get("article_ids")
    if not isinstance(article_ids, list) or not article_ids or not all(isinstance(a, str) and a.strip() for a in article_ids):
        raise GuardError(f"{diploma_id} article_ids must be a non-empty string array")


def _corpus_articles(corpus_path: str, diploma_id: str) -> dict[str, dict]:
    corpus = _load_json(corpus_path)
    if isinstance(corpus, dict):
        diplomas = corpus.get("diplomas", [])
    else:
        diplomas = corpus
    for diploma in diplomas:
        if diploma.get("id") == diploma_id:
            return {article["number"]: article for article in diploma.get("articles", [])}
    raise GuardError(f"corpus does not contain diploma {diploma_id}")


def build_report(manifest_path: str, corpus_path: str, artifact_path: str, diploma_id: str | None) -> dict:
    manifest = _load_manifest(manifest_path)
    artifact_abs = os.path.abspath(artifact_path)
    if not os.path.isfile(artifact_abs):
        raise GuardError(f"artifact does not exist: {artifact_abs}")
    actual_sha256 = _sha256_file(artifact_abs)
    capture = _find_capture(manifest, manifest_path, artifact_abs, diploma_id)
    _validate_approved_capture(capture, artifact_abs, actual_sha256)

    diploma_id = capture["diploma_id"]
    corpus_articles = _corpus_articles(corpus_path, diploma_id)
    covered = []
    already_verified = []
    unknown = []
    for article_id in capture["article_ids"]:
        article = corpus_articles.get(article_id)
        if article is None:
            unknown.append(article_id)
        elif article.get("verification") == "Verified":
            already_verified.append(article_id)
        else:
            covered.append(article_id)
    if unknown:
        raise GuardError(f"{diploma_id} capture lists articles absent from corpus: {', '.join(unknown)}")

    covered_set = set(capture["article_ids"])
    pending_uncovered = [
        article_id
        for article_id, article in corpus_articles.items()
        if article.get("verification") != "Verified" and article_id not in covered_set
    ]

    return {
        "dry_run": True,
        "status": "ok",
        "artifact_path": artifact_abs,
        "actual_sha256": actual_sha256,
        "diploma_id": diploma_id,
        "approval_marker": capture["approval_marker"],
        "would_promote_articles": covered,
        "already_verified_covered_articles": already_verified,
        "pending_uncovered_articles": pending_uncovered,
        "note": "No files were changed; promotion requires a separate vendoring step.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an approved rendered DRE artifact and print a dry-run promotion report."
    )
    parser.add_argument("artifact", help="path to the rendered DRE artifact")
    parser.add_argument("--diploma-id", help="required when the same artifact path is listed more than once")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, help="capture manifest path")
    parser.add_argument("--corpus", default=DEFAULT_CORPUS, help="law corpus JSON path")
    args = parser.parse_args()

    try:
        report = build_report(args.manifest, args.corpus, args.artifact, args.diploma_id)
    except (OSError, json.JSONDecodeError, GuardError) as exc:
        print(f"dre_approved_artifact_guard: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
