#!/usr/bin/bash
set -e
source ./setup_paths.conf
rm -f "$DS_ZIP"
rm -f "$DS_GZ"
rm -fr "data/$DATASET"
