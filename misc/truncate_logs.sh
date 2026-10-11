#!/bin/bash

set -euo pipefail

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  cat <<'EOF'
Usage: sudo ./misc/truncate_logs.sh [--] [LOG_FILE ...]

引数なし: /var/log/mysql/slow.log と /var/log/nginx/access.log を空にする。
引数あり: 指定したログファイルだけを空にする。
ファイルの所有者・パーミッションを維持し、存在しないファイルは作成しない。
EOF
  exit 0
fi

if [[ ${1:-} == -- ]]; then
  shift
fi

if (( $# == 0 )); then
  set -- /var/log/mysql/slow.log /var/log/nginx/access.log
fi

# すべて確認してから空にすることで、パスの誤指定による部分実行を防ぐ。
for log_file in "$@"; do
  if [[ ! -f "$log_file" ]]; then
    printf '通常ファイルが存在しません: %s\n' "$log_file" >&2
    exit 1
  fi
  if [[ ! -w "$log_file" ]]; then
    printf '書き込み権限がありません（sudoで実行してください）: %s\n' "$log_file" >&2
    exit 1
  fi
done

for log_file in "$@"; do
  truncate --no-create --size=0 -- "$log_file"
  printf 'Truncated: %s\n' "$log_file"
done
