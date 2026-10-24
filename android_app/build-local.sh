#!/bin/sh
set -eu
cd "$(dirname "$0")"
BASE=$(pwd)
mkdir -p "$BASE/.build-home/gradle" "$BASE/.build-home/tmp" "$BASE/.build-home/android"
export GRADLE_USER_HOME="$BASE/.build-home/gradle"
export ANDROID_USER_HOME="$BASE/.build-home/android"
export ANDROID_EMULATOR_HOME="$BASE/.build-home/android"
export TMPDIR="$BASE/.build-home/tmp"
if [ -z "${JAVA_HOME:-}" ] && [ -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]; then
    export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
export JAVA_TOOL_OPTIONS="-Duser.home=$BASE/.build-home -Djava.io.tmpdir=$BASE/.build-home/tmp"
python3 "$BASE/scripts/refresh-builtin-fixtures.py"
exec sh ./gradlew --project-cache-dir "$BASE/.build-home/project-cache" --no-daemon -Dorg.gradle.java.installations.auto-download=false "$@"
