"""Single source of truth for the active immutable public-evaluation release."""
from __future__ import annotations

PUBLIC_VERSION = "2.2.6-public-eval"
PROJECT_VERSION = "2.2.6"
TAG = "v2.2.6-public-eval"
PREVIOUS_TAG = "v2.2.5-public-eval"
ASSET_NAME = "permit-receipt-ref-eval-v2_2_6-public-eval.zip"
SIDECAR_NAME = ASSET_NAME + ".sha256"
MANIFEST_NAME = ASSET_NAME + ".manifest.json"
PROVENANCE_NAME = ASSET_NAME + ".provenance.json"
ROOT_DIR_NAME = "permit-receipt-main"
REPOSITORY = "meridianverity/permit-receipt"
RELEASE_TITLE = "v2.2.6 Public Evaluation — IETF 126 Review Packet"
RELEASE_URL = f"https://github.com/{REPOSITORY}/releases/tag/{TAG}"
BUILD_DATE = "2026-07-10"
NORMALIZED_ZIP_TIME = (2026, 7, 10, 0, 0, 0)
ARTIFACT_LABEL = "PermitReceipt Public Evaluation Slice for AI-Agent External Effects v2.2.6"
