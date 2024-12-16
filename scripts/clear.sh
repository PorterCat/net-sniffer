#!/usr/bin/sh

cd $(dirname $0)
outDir=$(cat ./OutDirName)
rm -rf ../${outDir}
