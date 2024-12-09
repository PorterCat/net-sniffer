# net-sniffer
Simple sniffer exmaple written in C++ using POSIX sockets.
## Build
```shell
./scripts/clean.sh                  # Recursively delete build files folder if exists (optional)
./scripts/generate-project-files.sh # Generate build files
./scripts/build.sh                  # Build using generated build files 
```
OR
```shell
./scripts/rebuild.sh # clean && generate-project-files && build
```
