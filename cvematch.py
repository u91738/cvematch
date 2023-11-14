#!/usr/bin/python3

import sys
from pathlib import Path
import multiprocessing
from gensim.models.keyedvectors import KeyedVectors
import cvm
import argparse
import cProfile
import traceback

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
ap.add_argument('--levenstein-ins-cost', default=1, type=float, help='insertion cost in levenstein distance computation')
ap.add_argument('--levenstein-del-cost', default=1, type=float, help='deletion cost in levenstein distance computation')
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

    #self_test(db, cve)
    if cve_ids:
        print('Will check:')
        print('\n'.join(cve_ids))
        cves = [cve for cve_id in cve_ids for cve in get_cve(db, conf, cve_id)]
    else:
        print('No CVEs to check. Will use all C/C++ CVE records')
        cves = get_cves(db, conf)
    print('In', len(arg.files), 'files')


    q = multiprocessing.Queue()
    def analyze(fname):
        '''Worker process job'''
        try:
            if arg.debug_profile:
                pr = cProfile.Profile()
                pr.enable()

            with open(fname, 'r') as f:
                tokens = cvm.tokenize(f.read())
            for cve in cves:
                path_b, score_b, score_a = cve.match_tokens(tokens)
                if score_b is not None and (score_a is None or score_b < score_a):
                    q.put((path_b, score_b, score_a, cve.change_id, fname))

            if arg.debug_profile:
                pr.disable()
                pr.print_stats(sort='tottime')
        except:
            traceback.print_exc()

    with multiprocessing.Pool() as pool:
        r = pool.map_async(analyze, arg.files)
        while not r.ready() or not q.empty():
            try:
                path_b, score_b, score_a, change_id, fname = q.get(timeout=0.3)
            except multiprocessing.queues.Empty:
                pass
            else:
                [(cve_id, cve_desc, cwe_id, cwe_name, _, diff)] = db.cve_report(change_id)
                print('Match with', cve_id, 'with score', score_b, '-', score_a)
                if arg.report_cve_info:
                    print('CVE Info:', cve_desc)
                if arg.report_cwe:
                    if cwe_id is None:
                        print('No CWE assigned')
                    else:
                        print(cwe_id, '-', cwe_name)
                if arg.report_diff_full:
                    print('diff:')
                    print(diff)
                with open(fname, 'r') as f:
                    tokens = cvm.tokenize(f.read(), get_line=True)
                    for i in path_b:
                        print(f'{fname}:{tokens[i.position]}:0')
                        if arg.report_diff:
                            print(i.src)
                print('')
