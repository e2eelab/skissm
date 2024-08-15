#!/bin/bash
version=$(git describe --tags --abbrev=0)

# doxygen -g docs/skissm-doxygen.cfg
doxygen docs/skissm-doxygen.cfg

# another way:
# docker run --rm -v $(pwd)/docs:/tmp/docs tsgkadot/docker-doxygen doxygen /tmp/docs
