#!/usr/bin/sh

baseDir=$(dirname $0)
outDir=$(cat ${baseDir}/OutDirName)
cd ${baseDir}/..
conan install . --output-folder=${baseDir}/../${outDir} --build=missing --profile=debug
