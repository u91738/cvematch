#!/usr/bin/bash
set -e

for lang in C C++ Java JavaScript C# Python PHP ; do
    if [ -e "data/w2v-$lang-cbow-v128-w5" ] ; then
        echo "$lang already has a default word2vec model"
    else
        echo "$lang"
        time ./w2v.py --lang "$lang" --vector-size 128 --window-size 5
    fi
done
