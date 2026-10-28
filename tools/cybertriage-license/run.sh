#!/usr/bin/env sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec java -cp "$script_dir/build" com.cybertriage.tools.license4j.License4JKeyPairGenerator "$@"
