#!/usr/bin/sh

cd $(dirname $0)
outDir=$(cat ./OutDirName)
cmake --build ../${outDir} $@
