all:
	ln -sf ~/dotfiles_catatsuy/.screenrc ~/.screenrc_catatsuy
	cp ~/dotfiles_catatsuy/.toprc ~/.toprc
	echo "\nscreen -S catatsuy -c ~/.screenrc_catatsuy\n"
