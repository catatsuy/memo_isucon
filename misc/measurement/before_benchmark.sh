#!/bin/bash
# 参考例。実環境のサービス名・ログパスに置き換え、不要な行は削除する。
# 「計測準備」時のみ競技サーバー上で実行する。
set -euo pipefail
cd "$(dirname "$0")"

sudo -n systemctl is-active --quiet nginx mysql
sudo -n test -f /var/log/nginx/access.log
sudo -n test -w /var/log/nginx/access.log
sudo -n test -f /var/log/mysql/slow.log
sudo -n test -w /var/log/mysql/slow.log
printf '%s: 計測準備開始\n' "$(hostname)" | notify_slack
sudo -n truncate --no-create -s 0 /var/log/nginx/access.log /var/log/mysql/slow.log
printf '%s: 計測準備完了\n' "$(hostname)" | notify_slack
echo '計測準備完了'
