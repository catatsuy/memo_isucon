#!/bin/bash
# 参考例。実環境のログパス・alpの正規表現に置き換え、不要な行は削除する。
# 人間によるベンチマーク終了後、競技サーバー上で実行する。
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p results
output=$(mktemp -d "results/$(hostname)-$(date '+%Y%m%d-%H%M%S').XXXXXX")
echo "結果保存先: $output"
sudo -n cat /var/log/nginx/access.log > "$output/access.log"
sudo -n cat /var/log/mysql/slow.log > "$output/slow.log"
nice -n 19 alp ltsv --sort=sum --reverse < "$output/access.log" > "$output/alp.txt"
nice -n 19 pt-query-digest --limit 100% "$output/slow.log" > "$output/slowq.txt"

# 片方の通知に失敗しても、もう片方を送る。保存済みの結果は残す。
status=0
notify_slack -snippet -filename "$(hostname)-alp.txt" < "$output/alp.txt" || status=1
notify_slack -snippet -filename "$(hostname)-slowq.txt" < "$output/slowq.txt" || status=1
exit "$status"
