#!/bin/sh

writefile=$1
writestr=$2 

if [ "$#" != "2" ];
then
	printf "Incorrect Number of arguments. Two arguments are needed. Here is how to run it -->./writer.sh <dir> <string> \n"
	exit 1
else
	if [ ! -d "$1" ];
	then
		mkdir -p  "$(dirname ${writefile})"
	       	
		echo "${writestr}" > "${writefile}"	
		if [ $? -ne 0 ]; 
		then
   			printf "Failed to create Directory and write file in it."
   			exit 1
		fi
	else
		echo "${writestr}" > "${writefile}"
		if [ $? -ne 0 ]; 
		then
  			 printf "Failed to write file."
   			 exit 1
		fi
	fi
fi

