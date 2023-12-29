#!/usr/bin/python3
import os
import sys
from pathlib import Path
from gensim.models import Word2Vec
import cvm
import argparse

ap = argparse.ArgumentParser(
    usage='./w2v.py --vector-size 128 --window-size 5',
    description='script to train word2vec models on CVEFixes dataset')
ap.add_argument('--vector-size', default=128, type=int, help='word2vec vector size')
ap.add_argument('--window-size', default=5, type=int, help='word2vec window size')
ap.add_argument('--skip-gram', action='store_true', help='use skip-gram instead of CBOW for training')
ap.add_argument('--lang',
    choices=[
        'Batchfile', 'C', 'C#', 'C++', 'CoffeeScript', 'Erlang', 'Go', 'HTML',
        'Haskell', 'Java', 'JavaScript', 'Lua', 'Matlab', 'Objective-C', 'PHP',
        'Perl', 'PowerShell', 'Python', 'R', 'Ruby', 'Rust', 'SQL', 'Scala',
        'Shell', 'Swift', 'TypeScript'],
    required=True,
    help='programming language, case-sensitive')

arg = ap.parse_args()

datadir = Path(__file__).parent / 'data'
db_path = str(datadir / 'CVEfixes_v1.0.7.sqlite')
assert os.path.isfile(db_path)
assert os.path.isdir('data')

tokenizer = cvm.get_tokenizer(arg.lang)

print('Reading code from', db_path)
with cvm.Database(db_path) as db:
    sentences = [[w for _, w in tokenizer.tokenize(i)] for i in db.all_code(arg.lang)]
if sentences:
    print('Read', len(sentences), 'source files')
else:
    print('No code found. Is the language arg correct?', file=sys.stderr)
    exit(1)

w = Word2Vec(sentences,
                min_count = 1,
                vector_size = arg.vector_size,
                window = arg.window_size,
                sg=1 if arg.skip_gram else 0)
algo = 'sg' if arg.skip_gram else 'cbow'
fname = f'data/w2v-{arg.lang.lower()}-{algo}-v{arg.vector_size}-w{arg.window_size}'
w.wv.save(fname)
print('Saved to:', fname)
