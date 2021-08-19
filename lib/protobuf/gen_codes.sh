#!/bin/bash -e -x
# install protobuf and additional plugins
# ref: https://github.com/protocolbuffers/protobuf/blob/master/docs/third_party.md
#   protobuf
#     on Mac
#       brew install protobuf
#   protobuf-c
#     on Mac
#       brew install protobuf-c
#   swift-protobuf
#     on Mac
#       brew install swift-protobuf
# generate codes:
#   protoc -I=. --java_out=./exports/java e2ee_address.proto
#   protoc -I=. --js_out=./exports/js e2ee_address.proto
#   protoc -I=. --c_out=./exports/c e2ee_address.proto
#   protoc -I=. --cpp_out=./exports/cpp e2ee_address.proto
#   protoc -I=. --objc_out=./exports/objc e2ee_address.proto
#   protoc -I=. --swift_out=./exports/swift e2ee_address.proto

langs="c" # "c cpp java js objc swift"
PWD=`pwd`
for lang in $langs
do
  dir=$PWD/exports/$lang
  mkdir -p $dir
  for proto_file in $(ls *.proto)
  do
    protoc -I=. --"$lang"_out=$PWD/exports/$lang $proto_file
  done
done
