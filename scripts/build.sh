#!/usr/bin/sh
baseDir=$(dirname $0)
outDir=$(cat ${baseDir}/OutDirName)
cmake --build ${baseDir}/../${outDir} $@
