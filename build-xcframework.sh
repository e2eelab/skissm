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

xcodebuild -create-xcframework \
 -framework build/OS64/Release-iphoneos/skissm.framework \
 -framework build/SIMULATORARM64/Release-iphonesimulator/skissm.framework \
 -output build/skissm.xcframework