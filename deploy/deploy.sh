#!/bin/bash

set -x

./deploy_body.sh 2>&1 | notify_slack
