#!/bin/bash

ln -sf ~/dotfiles_catatsuy/.screenrc ~/.screenrc_catatsuy
cp ~/dotfiles_catatsuy/.toprc ~/.toprc

echo "screen -S catatsuy -c ~/.screenrc_catatsuy"
