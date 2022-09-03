#!/bin/sh
filesdir=$1
searchstr=$2 

if [ "$#" != "2" ];
then
	echo "Incorrect Number of arguments. Two arguments are needed. Here is how to run it -->./finder.sh <dir> <string>"
	exit 1
else
	if [ ! -d "$1" ];
	then 
		echo "$filesdir does not exists"
		exit 1
	else
		num_files=`find $1 -type f | wc -l`
		num_lines=`grep -r $2 $1 2>/dev/null|wc -l`
		echo "The number of files are $num_files and the number of matching lines are $num_lines"
	fi
fi
