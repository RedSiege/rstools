#!/bin/sh
#title           :linux-setup.sh
#description     :Setup a fresh linux box with customizations
#author          :Tim Medin @TimMedin tim@redsiege.com
#date            :20180120
#version         :1.0
#usage           :linux-setup.sh
#repository      :https://github.com/RedSiege/rstools
#notes           :Must be run as root

USERS="root tm mike"

sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y

# add packages
sudo apt -y install tmux screen xclip nmap nikto python-pip

for U in $USERS
do

	# check if user exists
	id -u $U 1>/dev/null 2>/dev/null
	if [ $? -eq 1 ]; then
		echo adding user $U
		sudo useradd -m $U
		echo adding user $U to sudo group
		sudo usermod -aG sudo $U
	fi

	# get path to ~/.bashrc for user
	BASHRC=`eval echo ~$1`/.bashrc

	pip install paramiko

	while read LINE; do
		grep "$LINE" $BASHRC >/dev/null || echo "$LINE" >> $BASHRC
	done <<-EOF
		alias ll='ls -al'
		alias lh='ls -hal'
		alias pbcopy='xclip -selection clipboard'
		alias pbpaste='xclip -selection clipboard -o'
		alias curl='curl -sA "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"' # Make curl silent when piping output
		alias curl='curl -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"' # Make curl not use a sketch user-agent
		alias ping='ping -n'
		alias grepc='grep --color=always'
		alias no_blank_lines='grep -v "^\s*$"'
		alias nbl=no_blank_lines
		alias upcase='tr [a-z] [A-Z]'
		alias lowcase='tr [A-Z] [a-z]'
		alias cd..='cd ..'
		alias dir='ls -al'
		alias cls=clear
		alias clr='reset;clear'
		alias sort_ip='sort -uV'
		alias find_ip='egrep -o "([0-9]{1,3}\.){3}[0-9]{1,3}"'
EOF

done
