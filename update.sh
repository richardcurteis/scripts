#!/bin/bash

path=`pwd`/$1
cmd=$2

function clone() {
	while IFS= read -r line
	do
        git clone $line
	done < $path
}

function pull() {
	for D in `find . -type d`
	do
		cd $D
		if [ -d .git ]; then
			git pull
		fi
	done
}

function abort() {
	echo "Usage: ./update.sh tools.txt clone || pull"
	echo "Valid arguments are 'pull' or 'clone'"
	exit 1
}

if [ "$2" == "clone" ]
then
	if [ -f $1 ]
	then
		cd /opt
		clone
	else
		abort
fi

elif [ "$2" == "pull" ]
then
	cd /opt
	pull
else
	abort
fi
