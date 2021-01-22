#!/bin/sh
#title           :linux-setup.sh
#description     :Setup a fresh linux box with customizations
#author          :Tim Medin @TimMedin tim@redsiege.com
#date            :20180120
#version         :1.0
#usage           :linux-setup.sh
#repository      :https://github.com/RedSiege/rstools
#notes           :Must be run as root

USERS="root user1 user2"

sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y

# add packages
sudo apt -y install tmux screen xclip nmap nikto python-pip iptables-persistent xmlstarlet openjdk-11-jdk

#Make OpenJDK 11 the default
# ref https://cobaltstrike.com/help-java-dependency
sudo update-java-alternatives -s java-1.11.0-openjdk-amd64

# setup motd
echo 'ClRoaXMgc3lzdGVtIGlzIG93bmVkIGJ5IFJlZCBTaWVnZSwgTExDLiAoY29udGFjdEByZWRzaWVn
ZS5jb20pChtbMDszMW0KICAgICAgIyMjIyAgICAgIyMjIyAgICAjIyMjIwogICAgICAjIyMjIyAg
ICAjIyMjICAgICMjIyMjCiAgICAgICMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKICAgICAgIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIwogICAgICAjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCiAgICAgICAjIyMj
IyMjIyMjIyMjIyMjIyMjIwogICAgICAgICMjIyMjIyMjIyMjIyMjIyMjIwogICAgICAgIyMjIyMj
IyMjIyMjIyMjIyMjIyMKICAgICAgICMjIyMjIyMjIyMjIyMjIyMjIyMjCiAgICAgICMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMKICAgICAgIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwogICAgICAjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjCiAgICAgICMjIyMgICAgIyMjIyMjIyAgICMjIyMjCiAgICAgIyMjIyMj
IyMgICMjIyMgICMjIyMjIyMjCiAgICAgIyMjIyMjIyMjICMjIyMgIyMjIyMjIyMjCiAgICAgIyMj
IyMjIyMjICAjIyMgIyMjIyMjIyMjCiAgICAgICAgICAjIyMjICAgICAgIyMjIwogICAgICAgICAg
ICAgIyAgICAgICMKG1swOzBtCgobWzA7MzFtIF9fX18gIF9fX19fIF9fX18gG1swOzBtIF9fX18g
X19fIF9fX19fIF9fX18gX19fX18KG1swOzMxbXwgIF8gXHwgX19fX3wgIF8gXBtbMDswbS8gX19f
fF8gX3wgX19fXy8gX19ffCBfX19ffAobWzA7MzFtfCB8XykgfCAgX3wgfCB8IHwgG1swOzBtXF9f
XyBcfCB8fCAgX3x8IHwgIF98ICBffCAgChtbMDszMW18ICBfIDx8IHxfX198IHxffCAbWzA7MG18
X19fKSB8IHx8IHxfX3wgfF98IHwgfF9fXwobWzA7MzFtfF98IFxffF9fX19ffF9fX18vG1swOzBt
fF9fX198X19ffF9fX19fXF9fX198X19fX198CgpXQVJOSU5HOiBVbmF1dGhvcml6ZWQgYWNjZXNz
IHRvIHRoaXMgc3lzdGVtIGlzIGZvcmJpZGRlbiBhbmQgd2lsbCBiZQpwcm9zZWN1dGVkIGJ5IGxh
dy4gQnkgYWNjZXNzaW5nIHRoaXMgc3lzdGVtLCB5b3UgYWdyZWUgdGhhdCB5b3VyIGFjdGlvbnMK
bWF5IGJlIG1vbml0b3JlZCBpZiB1bmF1dGhvcml6ZWQgdXNhZ2UgaXMgc3VzcGVjdGVkLiBEaXNj
b25uZWN0IGltbWVkaWF0ZWx5CmlmIHlvdSBhcmUgbm90IGFuIGF1dGhvcml6ZWQgdXNlci4KCg==' | base64 -d > /etc/motd

for U in $USERS
do

	# check if user exists
	id -u $U 1>/dev/null 2>/dev/null
	if [ $? -eq 1 ]; then
		echo adding user $U
		sudo useradd -m $U -s /bin/bash
		echo adding user $U to sudo group
		sudo usermod -aG sudo $U
	fi

	# get path to ~/.bashrc for user
	BASHRC=`eval echo ~$1`/.bashrc

	while read LINE; do
		grep "$LINE" $BASHRC >/dev/null || echo "$LINE" >> $BASHRC
	done <<-EOF
		alias ll='ls -al'
		alias lh='ls -hal'
		alias pbcopy='xclip -selection clipboard'
		alias pbpaste='xclip -selection clipboard -o'
		#alias curl='curl -sA "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"' # Make curl silent when piping output
		alias curl='curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36"' # Make curl not use a sketch user-agent
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
