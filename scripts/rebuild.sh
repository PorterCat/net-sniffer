#!/usr/bin/sh

cd $(dirname $0)

./clear.sh
./generate-project-files.sh
./build.sh
