#!/bin/sh
# Run the Swift tests. This is the one place that knows where the test
# frameworks live when only Command Line Tools are installed. With full Xcode
# installed, plain `swift test` works and this script is not needed.
#
#   signer/apple/scripts/test.sh [swift test arguments]
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
frameworks=/Library/Developer/CommandLineTools/Library/Developer/Frameworks
libs=/Library/Developer/CommandLineTools/Library/Developer/usr/lib

if [ ! -d "$frameworks/Testing.framework" ]; then
    echo "test.sh: $frameworks/Testing.framework is missing; install Command Line Tools or Xcode" >&2
    exit 1
fi
if [ ! -d "$libs" ]; then
    echo "test.sh: $libs is missing; install Command Line Tools or Xcode" >&2
    exit 1
fi

exec swift test --package-path "$here" \
    -Xswiftc -F -Xswiftc "$frameworks" \
    -Xlinker -F -Xlinker "$frameworks" \
    -Xlinker -rpath -Xlinker "$frameworks" \
    -Xlinker -rpath -Xlinker "$libs" \
    "$@"
