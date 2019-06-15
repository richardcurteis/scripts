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
	cd /opt
	for D in `find . -type d`
	do
		cd $D
		if [ -d .git ]; then
			git pull
		fi 
	done
}

cd /opt
if [ $2 -eq "clone"]
then
	clone

elif [ $2 -eq "pull"]
then
	pull
else
	echo "Valid arguments are 'pull' or 'clone'"
fi
