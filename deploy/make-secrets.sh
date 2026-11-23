#!/usr/bin/env sh
# Generates the KMS root key used by docker-compose.yml as a Docker secret.
# The key never enters the image, the compose file or version control
# (deploy/secrets/ is git-ignored). Losing it makes every stored file unreadable.
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p secrets
if [ -s secrets/kms_root_key ]; then
  echo "secrets/kms_root_key already exists; not overwriting" >&2
  exit 0
fi
head -c 32 /dev/urandom | base64 > secrets/kms_root_key
# The backend container runs as uid 10001 and reads the secret file.
chmod 0444 secrets/kms_root_key 2>/dev/null || true
echo "wrote deploy/secrets/kms_root_key (keep it safe; back it up out of band)"
