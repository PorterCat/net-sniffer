#!/usr/bin/sh
baseDir=$(dirname $0)
${baseDir}/clear.sh
${baseDir}/run-conan.sh
${baseDir}/generate-project-files.sh
${baseDir}/build.sh
