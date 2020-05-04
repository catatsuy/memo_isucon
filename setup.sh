#!/bin/bash

ln -sf ~/dotfiles_catatsuy/.tmux.conf ~/.tmux_catatsuy.conf

echo "tmux new -s catatsuy"
echo "tmux a -t catatsuy"
echo "tmux kill-session -t catatsuy"
