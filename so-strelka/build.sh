#!/bin/bash

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "This program needs root privileges.  Please try again using sudo."
    exit
fi
tag="HH1.1.4"
cwd=$(pwd)
prefix="so-strelka-"
repo="soshybridhunter"
if [ -d strelka ]; then 
    rm -rf strelka
fi
git clone https://github.com/target/strelka
for i in backend filestream frontend manager; do 
	cd $cwd/$i;
        echo $(pwd)
        docker build -t $repo/$prefix$i:$tag -f $cwd/$i/Dockerfile $cwd/strelka/. 
done
