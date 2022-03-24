# #!/bin/bash

BUILD_TYPE="Debug"
rm -rf build

cmake -S . --preset ios
cmake --build --preset ios

cmake -S . --preset ios_SIMULATOR64
cmake --build --preset ios_SIMULATOR64

cmake -S . --preset ios_SIMULATORARM64
cmake --build --preset ios_SIMULATORARM64

XCFRAMEWORK_DIR="build/skissm.xcframework"
PLISTBUDDY_EXEC="/usr/libexec/PlistBuddy"

rm -rf "${XCFRAMEWORK_DIR}"
mkdir "${XCFRAMEWORK_DIR}"

INFO_PLIST="${XCFRAMEWORK_DIR}/Info.plist"
"$PLISTBUDDY_EXEC" -c "Add :CFBundlePackageType string XFWK"  "${INFO_PLIST}"
"$PLISTBUDDY_EXEC" -c "Add :XCFrameworkFormatVersion string 1.0"  "${INFO_PLIST}"
"$PLISTBUDDY_EXEC" -c "Add :AvailableLibraries array" "${INFO_PLIST}"

plist_add_library() {
    local index=$1
    local identifier=$2
    local platform=$3
    local platform_variant=$4
    "$PLISTBUDDY_EXEC" -c "Add :AvailableLibraries: dict"  "${INFO_PLIST}"
    "$PLISTBUDDY_EXEC" -c "Add :AvailableLibraries:${index}:LibraryIdentifier string ${identifier}"  "${INFO_PLIST}"
    "$PLISTBUDDY_EXEC" -c "Add :AvailableLibraries:${index}:LibraryPath string skissm.framework"  "${INFO_PLIST}"
    "$PLISTBUDDY_EXEC" -c "Add :AvailableLibraries:${index}:SupportedArchitectures array"  "${INFO_PLIST}"
    "$PLISTBUDDY_EXEC" -c "Add :AvailableLibraries:${index}:SupportedPlatform string ${platform}"  "${INFO_PLIST}"
    if [ ! -z "$platform_variant" ]; then
        "$PLISTBUDDY_EXEC" -c "Add :AvailableLibraries:${index}:SupportedPlatformVariant string ${platform_variant}" "${INFO_PLIST}"
    fi
}

plist_add_architecture() {
    local index=$1
    local arch=$2
    "$PLISTBUDDY_EXEC" -c "Add :AvailableLibraries:${index}:SupportedArchitectures: string ${arch}"  "${INFO_PLIST}"
}

IOS_LIB_IDENTIFIER="ios-arm64"
IOS_SIM_LIB_IDENTIFIER="ios-x86_64_arm64-simulator"

mkdir -p "${XCFRAMEWORK_DIR}/${IOS_LIB_IDENTIFIER}"
mkdir -p "${XCFRAMEWORK_DIR}/${IOS_SIM_LIB_IDENTIFIER}"

LIB_IOS_INDEX=0
LIB_IOS_SIMULATOR_INDEX=1

plist_add_library $LIB_IOS_INDEX $IOS_LIB_IDENTIFIER "ios"
plist_add_library $LIB_IOS_SIMULATOR_INDEX $IOS_SIM_LIB_IDENTIFIER "ios" "simulator"

cp -r build/ios/${BUILD_TYPE}-iphoneos/skissm.framework "${XCFRAMEWORK_DIR}/${IOS_LIB_IDENTIFIER}"
cp -r build/ios_SIMULATOR64/${BUILD_TYPE}-iphonesimulator/skissm.framework "${XCFRAMEWORK_DIR}/${IOS_SIM_LIB_IDENTIFIER}"

LIPO_IOS_FLAGS="build/ios/${BUILD_TYPE}-iphoneos/skissm.framework/skissm"
LIPO_IOS_SIM_FLAGS="build/ios_SIMULATOR64/${BUILD_TYPE}-iphonesimulator/skissm.framework/skissm build/ios_SIMULATORARM64/${BUILD_TYPE}-iphonesimulator/skissm.framework/skissm"

plist_add_architecture $LIB_IOS_INDEX "arm64"
plist_add_architecture $LIB_IOS_SIMULATOR_INDEX "arm64"
plist_add_architecture $LIB_IOS_SIMULATOR_INDEX "x86_64"

lipo -create -output  "${XCFRAMEWORK_DIR}/${IOS_LIB_IDENTIFIER}/skissm.framework/skissm" ${LIPO_IOS_FLAGS}
lipo -create -output "${XCFRAMEWORK_DIR}/${IOS_SIM_LIB_IDENTIFIER}/skissm.framework/skissm" ${LIPO_IOS_SIM_FLAGS}

echo "${XCFRAMEWORK_DIR} is successfully generated!"
