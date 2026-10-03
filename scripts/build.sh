#!/bin/zsh
# Builds DayBookEvtxMacOS (Release) into build/DayBookEvtxMacOS.app and the evtxdump CLI.
#   scripts/build.sh            # app + CLI
#   open build/DayBookEvtxMacOS.app
set -euo pipefail
cd "${0:A:h}/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

log=build/xcodebuild.log
mkdir -p build
if ! xcodebuild -project DayBookEvtxMacOS.xcodeproj -scheme DayBookEvtxMacOS -configuration Release \
        -derivedDataPath build/DerivedData.noindex build > "$log" 2>&1; then
    grep -E "error:" "$log" | head -20
    echo "App build failed, full log: $log"
    exit 1
fi
rm -rf build/DayBookEvtxMacOS.app
ditto build/DerivedData.noindex/Build/Products/Release/DayBookEvtxMacOS.app build/DayBookEvtxMacOS.app
echo "App: $PWD/build/DayBookEvtxMacOS.app"

(cd Packages/DaybookKit && swift build -c release > ../../build/swiftbuild.log 2>&1) || {
    echo "CLI build failed, log: build/swiftbuild.log"
    exit 1
}
echo "CLI: $PWD/Packages/DaybookKit/.build/release/evtxdump"
