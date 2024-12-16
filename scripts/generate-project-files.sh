#!/usr/bin/sh

cd $(dirname $0)
outDir=$(cat ./OutDirName)
cd ..
cmake . -B ./${outDir} $@