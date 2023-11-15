#!/usr/bin/bash
set -e

source ./setup_paths.conf

if [ ! -e data ] ; then
    mkdir data
fi

if [ ! -e "$DS_ZIP" ] ; then
    echo "Download dataset $DATASET"
    echo 'For dataset description see https://zenodo.org/records/7029359'
	wget --show-progress -O "$DS_ZIP" "https://zenodo.org/records/7029359/files/$DATASET.zip"
fi

if [ ! -e "$DS_GZ" ] ; then
    echo 'Extract sql from dataset zip'
    unzip "$DS_ZIP" "$DATASET/Data/$DATASET.sql.gz" -d data
fi

if [ ! -e "$DB" ] ; then
    echo "Convert dataset to sqlite $DB"
    echo "sqlite version: $(sqlite3 -version)"
    time gzip -d < "$DS_GZ" | sqlite3 "$DB"
fi

if [ ! -e "$DB" ] ; then
    echo "Something went very wrong $DB still doesn't exist"
    exit 1
fi

DB_SIZE=$(stat --format='%s' "$DB")
if [ "$DB_SIZE" -gt 4000000000 ] ; then
    echo 'Dataset is big, shrink it'
    sqlite3 "$DB" < cvm/sql/prepare_db.sql
fi

if [ ! -e data/w2v-cbow-v128-w5 ] ; then
    echo 'No word2vec files found. Generate some'
    echo 'Vector size 128, window size 5'
    time ./w2v.py --vector-size 128 --window-size 5
fi

echo 'Done. You can run ./cleanup.sh to free some space'
