#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

rm -rf build
mkdir -p build

find src/main/java -name '*.java' -print > build/sources.txt
javac -encoding UTF-8 -d build @build/sources.txt

echo "Built classes in $(pwd)/build"
