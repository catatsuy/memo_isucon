#!/bin/bash

set -x

echo "start deploy ${USER}"
GOOS=linux GOARCH=amd64 go build -o isucari_linux
for server in isu01 isu02; do
  ssh -t $server "sudo systemctl stop isucari.golang.service"
  # for build on Linux
  # rsync -vau --exclude=app ./ $server:/home/isucon/private_isu/webapp/golang/
  # ssh -t $server "cd /home/isucon/private_isu/webapp/golang; PATH=/home/isucon/.local/go/bin/:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin make"

  scp ./isucari_linux $server:/home/isucon/isucari/webapp/go/isucari
  # rsync -vau ../sql/ $server:/home/isucon/isucari/webapp/sql/
  ssh -t $server "sudo systemctl start isucari.golang.service"
done

echo "finish deploy ${USER}"
