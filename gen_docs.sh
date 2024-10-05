#!/bin/bash
export api_ver=$(git describe --tags --abbrev=0)
export ts_ver="v1.0"

# gen spec doc
mkdir -p docs/spec
find docs/spec/* -delete
# generate default cfg: doxygen -g docs/skissm-tests-doxygen.cfg
doxygen docs/skissm-tests-doxygen.cfg

# gen api doc
mkdir -p docs/api
find docs/api/* -delete
# generate default cfg: doxygen -g docs/skissm-doxygen.cfg
doxygen docs/skissm-doxygen.cfg
