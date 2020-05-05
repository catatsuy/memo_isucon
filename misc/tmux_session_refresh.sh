#!/bin/bash

set -e

if [ -n "$TMUX" ]; then
  unset $(tmux show-env | sed -n 's/^-//p')
  eval export $(tmux show-env | sed -n 's/$/"/; s/=/="/p')
fi
