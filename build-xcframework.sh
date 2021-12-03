#!/bin/bash
rm -rf build

mkdir -p build/OS64
pushd build/OS64
cmake -G Xcode \
    -DCMAKE_TOOLCHAIN_FILE=../../cmake/ios.toolchain.cmake \
    -DPLATFORM=OS64 \
    -DDEPLOYMENT_TARGET=13.0 \
    -DENABLE_BITCODE=ON \
    -DENABLE_VISIBILITY=ON \
    -DENABLE_STRICT_TRY_COMPILE=ON \
    -DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO \
    ../..
cmake --build . --config Release
popd

mkdir -p build/SIMULATOR64
pushd build/SIMULATOR64
cmake -G Xcode \
    -DCMAKE_TOOLCHAIN_FILE=../../cmake/ios.toolchain.cmake \
    -DPLATFORM=SIMULATOR64 \
    -DDEPLOYMENT_TARGET=13.0 \
    -DENABLE_BITCODE=ON \
    -DENABLE_VISIBILITY=ON \
    -DENABLE_STRICT_TRY_COMPILE=ON \
    -DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO \
    ../..
cmake --build . --config Release
popd

mkdir -p build/SIMULATORARM64
pushd build/SIMULATORARM64
cmake -G Xcode \
    -DCMAKE_TOOLCHAIN_FILE=../../cmake/ios.toolchain.cmake \
    -DPLATFORM=SIMULATORARM64 \
    -DDEPLOYMENT_TARGET=13.0 \
    -DENABLE_BITCODE=ON \
    -DENABLE_VISIBILITY=ON \
    -DENABLE_STRICT_TRY_COMPILE=ON \
    -DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO \
    ../..
cmake --build . --config Release
popd

XCFRAMEWORK_DIR="build/skissm.xcframework"
PLISTBUDDY_EXEC="/usr/libexec/PlistBuddy"
INFO_PLIST="${XCFRAMEWORK_DIR}/Info.plist"

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

cp -r build/OS64/Release-iphoneos/skissm.framework "${XCFRAMEWORK_DIR}/${IOS_LIB_IDENTIFIER}"
cp -r build/SIMULATOR64/Release-iphonesimulator/skissm.framework "${XCFRAMEWORK_DIR}/${IOS_SIM_LIB_IDENTIFIER}"

LIPO_IOS_FLAGS="build/OS64/Release-iphoneos/skissm.framework/skissm"
LIPO_IOS_SIM_FLAGS="build/SIMULATOR64/Release-iphonesimulator/skissm.framework/skissm build/SIMULATORARM64/Release-iphonesimulator/skissm.framework/skissm"

plist_add_architecture $LIB_IOS_INDEX "arm64"
plist_add_architecture $LIB_IOS_SIMULATOR_INDEX "arm64"
plist_add_architecture $LIB_IOS_SIMULATOR_INDEX "x86_64"

lipo -create -output  "${XCFRAMEWORK_DIR}/${IOS_LIB_IDENTIFIER}/skissm.framework/skissm" ${LIPO_IOS_FLAGS}
lipo -create -output "${XCFRAMEWORK_DIR}/${IOS_SIM_LIB_IDENTIFIER}/skissm.framework/skissm" ${LIPO_IOS_SIM_FLAGS}

echo "${XCFRAMEWORK_DIR} is successfully generated!"
