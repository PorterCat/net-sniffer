#!/usr/bin/sh
baseDir=$(dirname $0)
outDir=$(cat ${baseDir}/OutDirName)
echo ${baseDir}/OutDirName
cd ${baseDir}/..

cmake . -B ${baseDir}/../${outDir} $@
