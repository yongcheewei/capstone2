#!/usr/bin/env bash
# Download the Loghub Linux_auth dataset and place it under data/raw/.
# Requires: curl, unzip
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p data/raw
URL="https://github.com/logpai/loghub/raw/master/Linux/Linux.tar.gz"
OUT="data/raw/Linux.tar.gz"

if [ ! -f "$OUT" ]; then
  echo "[download_data.sh] fetching $URL"
  curl -L "$URL" -o "$OUT"
fi

mkdir -p data/raw/Linux
tar -xzf "$OUT" -C data/raw/Linux || true

cat <<EOF
[download_data.sh] done.
Look for syslog logs under data/raw/Linux/.
The recommended file is Linux/Linux.log or a sample auth.log from Loghub.
Adjust data/processed/groundtruth_ips.txt to mark attack IPs accordingly.
EOF
