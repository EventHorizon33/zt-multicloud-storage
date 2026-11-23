"""Create the bucket/container on the local emulators using the application's
own adapters (so the same SDK code path is exercised).

Usage: ensure_buckets.py [s3|azure|gcs ...]   (default: all three)
Reads the ZT_* variables written by scripts/emulators.sh. Refuses to run
against anything that is not an emulator endpoint.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts import StorageError  # noqa: E402
from app.storage.azure import AzureBlobProvider  # noqa: E402
from app.storage.gcs import GCSProvider  # noqa: E402
from app.storage.s3 import S3Provider  # noqa: E402


def _build(which: str):
    env = os.environ
    if which == "s3":
        endpoint = env.get("ZT_S3_ENDPOINT_URL")
        if not endpoint:
            raise SystemExit("ZT_S3_ENDPOINT_URL is not set: refusing to create buckets on real AWS")
        return S3Provider(bucket=env.get("ZT_S3_BUCKET", "zt-chunks"), endpoint_url=endpoint,
                          region=env.get("ZT_S3_REGION", "us-east-1"),
                          access_key_id=env.get("ZT_S3_ACCESS_KEY_ID"),
                          secret_access_key=env.get("ZT_S3_SECRET_ACCESS_KEY"), timeout_seconds=5)
    if which == "azure":
        conn = env.get("ZT_AZURE_CONNECTION_STRING", "")
        if "devstoreaccount1" not in conn:
            raise SystemExit("connection string is not the Azurite development account: refusing")
        return AzureBlobProvider(connection_string=conn,
                                 container=env.get("ZT_AZURE_CONTAINER", "zt-chunks"), timeout_seconds=5)
    if which == "gcs":
        endpoint = env.get("ZT_GCS_ENDPOINT_URL")
        if not endpoint:
            raise SystemExit("ZT_GCS_ENDPOINT_URL is not set: refusing to create buckets on real GCS")
        return GCSProvider(bucket=env.get("ZT_GCS_BUCKET", "zt-chunks"), endpoint_url=endpoint,
                           project=env.get("ZT_GCS_PROJECT"), timeout_seconds=5)
    raise SystemExit(f"unknown emulator: {which}")


def main(argv: list[str]) -> int:
    rc = 0
    for which in argv or ["s3", "azure", "gcs"]:
        provider = _build(which)
        last: Exception | None = None
        for _ in range(25):  # the port may answer slightly before the service is ready
            try:
                provider.ensure_bucket()
                status = provider.health()
                if status.healthy:
                    print(f"[{which}] bucket/container ready ({provider.name})")
                    last = None
                    break
                last = StorageError(status.error or "unhealthy")
            except StorageError as exc:
                last = exc
            time.sleep(0.2)
        if last is not None:
            print(f"[{which}] ERROR: could not prepare bucket: {last}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
