#!/usr/bin/python3

import sys
from pathlib import Path
import multiprocessing
from gensim.models.keyedvectors import KeyedVectors
import cvm
import argparse
import cProfile
import traceback
import more_itertools as mit
from collections import defaultdict
import numpy as np

def db_diff_to_git_diff(diff_str):
    return f'diff --git a/a.cpp b/a.cpp\nindex 0000..0000 000000\n' + diff_str

def get_cves(db, conf):
    res = []
    for file_change_id, diff_str in db.get_cves():
        diff = db_diff_to_git_diff(diff_str)
        if cve := cvm.CVEDesc.from_patch(conf, file_change_id, diff):
            res.append(cve)
    return res

def get_cve(db, conf, cve_id):
    res = []
    for file_change_id, diff_str in db.get_cve(cve_id):
        diff = db_diff_to_git_diff(diff_str)
        if cve := cvm.CVEDesc.from_patch(conf, file_change_id, diff):
            res.append(cve)
    return res

def w2v_show(w2v):
    print('word2vec distances')
    print('Should be close:')
    for a,b in [('+', '-'), ('if', 'while'), ('int', 'unsigned'), ('int', 'uint')]:
        print(a, b, ':', w2v.distance(a,b))
    print('Should be far:')
    for a,b in [('if', '/'), ('int', 'while'), ('int', '&&'), ('int', ';')]:
        print(a, '-', b, ':', w2v.distance(a,b))

def cve_show(db):
    for cve_id, cwe_id, desc in db.list_cves():
        print(cve_id, cwe_id)
        print(desc.strip('"'), '\n')

def cwe_show(db):
    for cwe_id, cwe_name, cve_count, desc in db.list_cwes():
        print(cwe_id, '-', cwe_name)
        print(desc.strip('"'))
        print('CVEs with this CWE:', cve_count, '\n')

ap = argparse.ArgumentParser(
    usage="./cvematch.py --report-diff --cve='CVE-1999-0199' --max-score 0.3 some/project/src/*.c",
    description='''Match known CVE fixes to your code.
                   The result should be interpreted as "structure of this code loosely reminds the code that lead to CVE-123"''')

ap.add_argument('--db',
                help='Path to database',
                default=None)
ap.add_argument('--cve', action='append', default=[], help='CVE id to check. Can be repeated.')
ap.add_argument('--cwe', action='append', default=[], help='Check all CVEs with this CWE id. Can be repeated.')
ap.add_argument('--no-cve', action='append', default=[], help='CVE id to not check. Can be repeated.')
ap.add_argument('--w2v-show', action='store_true', help='show distances to some word2vec tokens')
ap.add_argument('--w2v-list', action='store_true', help='list available word2vec files')
ap.add_argument('--w2v', default='w2v-cbow-v128-w5', help='word2vec files name to use, see --w2v-list')
ap.add_argument('--cve-list', action='store_true', help='show list of available CVEs')
ap.add_argument('--cwe-list', action='store_true', help='show list of available CWEs')
ap.add_argument('--report-cve-info', action='store_true', help='show CVE description for matches')
ap.add_argument('--report-cwe', action='store_true', help='show CWE id and description for matches')
ap.add_argument('--report-diff', action='store_true', help='on match, show diff for matching hunk in CVE fix')
ap.add_argument('--report-diff-full', action='store_true', help='on match, show full diff of CVE fix')
ap.add_argument('--debug-profile', action='store_true', help='profile the main analysis code')
ap.add_argument('--max-score', default=0.2, type=float,
                help='Max score value that is considered low enough to show as a result. Reasonable values are from 0.05 (~exact copy of CVE) to 0.3 (loosely reminds of some CVE)')
ap.add_argument('--levenstein-ins-cost', default=2, type=float, help='insertion cost in levenstein distance computation')
ap.add_argument('--levenstein-del-cost', default=2, type=float, help='deletion cost in levenstein distance computation')
ap.add_argument('files', nargs='*', help='Source files to check')


arg = ap.parse_args()

datadir = Path(__file__).parent / 'data'
if arg.db is None:
    arg.db = str(datadir / 'CVEfixes_v1.0.7.sqlite')

if arg.w2v_list:
    print('Available word2vec models w2v-(training algorithm)-v(vector-size)-w(window size):')

    for i in datadir.iterdir():
        if i.startswith('w2v-') and not i.endswith('.npy'):
            print(i)
    print()

w2v_fname = datadir / arg.w2v
if not w2v_fname.is_file():
    print('word2vec model', w2v_fname, 'not found', file=sys.stderr)
    print('Train it with something like ./w2v.py --vector-size 128 --window-size 5', file=sys.stderr)
    exit(-1)

w2v = KeyedVectors.load(str(w2v_fname))

if arg.w2v_show:
    w2v_show(w2v)


conf = cvm.MatcherConfig(w2v, arg.max_score, arg.levenstein_ins_cost, arg.levenstein_del_cost)

cve_ids = []
cve_ids += arg.cve

if arg.cwe:
    print('CWE filtering is not supported yet', file=sys.stderr)
    exit(1)

if arg.no_cve:
    for i in arg.no_cve:
        try:
            cve_ids.remove(i)
        except ValueError:
            pass

if not arg.files:
    print('No source files specified', file=sys.stderr)
    exit(1)

with cvm.Database(arg.db) as db:
    if arg.cve_list:
        cve_show(db)

    if arg.cwe_list:
        cwe_show(db)

    if cve_ids:
        print('Will check:')
        print('\n'.join(cve_ids))
        cves = [cve for cve_id in cve_ids for cve in get_cve(db, conf, cve_id)]
    else:
        print('No CVEs to check. Will use all C/C++ CVE records')
        cves = get_cves(db, conf)

    needles_before_map = defaultdict(lambda: [])
    needles_before = []
    for cve in cves:
        for hunk in cve.before:
            needles_before_map[cve].append(len(needles_before))
            needles_before.append(hunk.tokens)

    needles_after_map = defaultdict(lambda: [])
    needles_after = []
    for cve in cves:
        for hunk in cve.after:
            needles_after_map[cve].append(len(needles_after))
            needles_after.append(hunk.tokens)

    files = []
    for fname in arg.files:
        with open(fname, 'r') as f:
            files.append((fname, cvm.tokenize(f.read())))
    haystack_max = max(len(i[1]) for i in files)
    print(len(arg.files), 'files, max tokens in file: ', haystack_max)

    with (cvm.LevensteinSearchCL(conf.w2v,
                                 haystack_max,
                                 conf.levenstein_ins_cost,
                                 conf.levenstein_del_cost,
                                 max(conf.levenstein_ins_cost, conf.levenstein_del_cost)
          ) as lev,
          lev.prepare_needles(needles_before) as needles_b,
          lev.prepare_needles(needles_after) as needles_a,
          lev.prepare_haystack() as haystack
    ):
        print('OpenCL search running on ', ', '.join(i.name for i in lev.ctx.devices))
        for fname, tokens in files:
            print('Processing', fname, 'tokens:', len(tokens))
            haystack.assign(tokens)

            dist_b, ind = lev.search(needles_b, haystack)
            dist_a, _ = lev.search(needles_a, haystack)
            for cve in cves:
                hunk_inds = needles_before_map[cve]
                score_b = np.mean(dist_b[hunk_inds])
                score_a = np.mean(dist_a[needles_after_map[cve]])
                if score_b < conf.max_score and score_b < score_a:
                    r = db.cve_report(cve.change_id)
                    cve_rep = db.cve_report(cve.change_id)
                    print('Matched', cve_rep.cve_id, 'with score', score_b, '-', score_a)
                    if arg.report_cve_info:
                        print('CVE Info:', cve_rep.description)
                    if arg.report_cwe:
                        for cwe in cve_rep.cwe:
                            print(cwe.cwe_id, '-', cwe.cwe_name)
                    if arg.report_diff_full:
                        print('diff:')
                        print(cve_rep.diff)
                    with open(fname, 'r') as f:
                        tokens = cvm.tokenize(f.read(), get_line=True)
                        for hunk_ind, i in enumerate(ind[hunk_inds]):
                            print(f'{fname}:{tokens[i]}:0')
                            if arg.report_diff:
                                print(cve.before[hunk_ind].src)
                    print('')
