#!/usr/bin/python3
import os
import sys
from gensim.models import Word2Vec
import cvm
import argparse

ap = argparse.ArgumentParser(
    usage='./w2v.py --vector-size 128 --window-size 5',
    description='script to train word2vec models on CVEFixes dataset')
ap.add_argument('--db',
                default='data/CVEfixes_v1.0.7.sqlite',
                help='Path to database')
ap.add_argument('--vector-size', default=128, type=int, help='word2vec vector size')
ap.add_argument('--window-size', default=5, type=int, help='word2vec window size')
ap.add_argument('--skip-gram', action='store_true', help='use skip-gram instead of CBOW for training')
arg = ap.parse_args()

assert os.path.isfile(arg.db)
assert os.path.isdir('data')

print('Reading code from', arg.db)
with cvm.Database(arg.db) as db:
    sentences = [cvm.tokenize(i) for (i,) in db.all_code()]
print('Read', len(sentences), 'source files')
w = Word2Vec(sentences,
                min_count = 1,
                vector_size = arg.vector_size,
                window = arg.window_size,
                sg=1 if arg.skip_gram else 0)
algo = 'sg' if arg.skip_gram else 'cbow'
fname = f'data/w2v-{algo}-v{arg.vector_size}-w{arg.window_size}'
w.wv.save(fname)
print('Saved to:', fname)
