#!/bin/bash
export api_ver=$(git describe --tags --abbrev=0)
export ts_ver="v1.0"

mkdir -p docs/api
mkdir -p docs/spec
# doxygen -g docs/skissm-doxygen.cfg
# doxygen -g docs/skissm-tests-doxygen.cfg
doxygen docs/skissm-doxygen.cfg
doxygen docs/skissm-tests-doxygen.cfg

# another way:
# docker run --rm -v $(pwd)/docs:/tmp/docs tsgkadot/docker-doxygen doxygen /tmp/docs
