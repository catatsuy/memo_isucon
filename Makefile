all:
	ln -sf ~/dotfiles_catatsuy/.screenrc ~/.screenrc_catatsuy
	cp ~/dotfiles_catatsuy/.toprc ~/.toprc
	screen -S catatsuy -c ~/.screenrc_catatsuy
