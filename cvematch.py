#!/usr/bin/python3

import sys
from pathlib import Path
from gensim.models.keyedvectors import KeyedVectors
import cvm
import argparse

def db_diff_to_git_diff(diff_str):
    return f'diff --git a/a.cpp b/a.cpp\nindex 0000..0000 000000\n' + diff_str

def get_cves(db, min_hunk_tokens):
    res = []
    for file_change_id, cve_id, cwe_id, diff_str in db.get_cves():
        diff = db_diff_to_git_diff(diff_str)
        if cve := cvm.CVEDesc.from_patch(file_change_id, cve_id, cwe_id, diff, min_hunk_tokens):
            res.append(cve)
    return res

def get_cve(db, cve_id, min_hunk_tokens):
    res = []
    for file_change_id, cve_id, cwe_id, diff_str in db.get_cve(cve_id):
        diff = db_diff_to_git_diff(diff_str)
        if cve := cvm.CVEDesc.from_patch(file_change_id, cve_id, cwe_id, diff, min_hunk_tokens):
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
    usage="./cvematch.py --report-cve-info --report-cwe --report-diff --cve='CVE-1999-0199' some/project/src/*.c",
    description='''Match known CVE fixes to your code.
                   The result should be interpreted as "structure of this code loosely reminds the code that lead to CVE-123"''')

ap.add_argument('--db',
                help='Path to database',
                default=None)
ap.add_argument('--cve', action='append', default=[], help='CVE id to check. Can be repeated.')
ap.add_argument('--cwe', action='append', default=[], help='Check all CVEs with this CWE id. Can be repeated.')
ap.add_argument('--w2v-show', action='store_true', help='show distances to some word2vec tokens')
ap.add_argument('--w2v-list', action='store_true', help='list available word2vec files')
ap.add_argument('--w2v', default='w2v-cbow-v128-w5', help='word2vec files name to use, see --w2v-list')
ap.add_argument('--cve-list', action='store_true', help='show list of available CVEs')
ap.add_argument('--cwe-list', action='store_true', help='show list of available CWEs')
ap.add_argument('--report-cve-info', action='store_true', help='show CVE description for matches')
ap.add_argument('--report-cwe', action='store_true', help='show CWE id and description for matches')
ap.add_argument('--report-diff', action='store_true', help='on match, show diff for matching hunk in CVE fix')
ap.add_argument('--report-diff-full', action='store_true', help='on match, show full diff of CVE fix')
ap.add_argument('--report-diff-id', action='store_true', help='on match, show internal id of matched diff to be used in --ignore')
ap.add_argument('--ignore', action='append', default=[],
                help='CVE id, CWE id or diff id to ignore. See --cve-list, --cwe-list, --report-diff-id')
ap.add_argument('--ignore-file', help='file with --ignore args separated by new line')
ap.add_argument('--split-diffs', action='store_true', help='treat each hunk of file change as separate file diff')

ap.add_argument('--min-hunk-tokens', default=30, type=int,
                help='minimal token count for change to matter')
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
    exit()

w2v_fname = datadir / arg.w2v
if not w2v_fname.is_file():
    print('word2vec model', w2v_fname, 'not found', file=sys.stderr)
    print('Train it with something like ./w2v.py --vector-size 128 --window-size 5', file=sys.stderr)
    exit(1)

w2v = KeyedVectors.load(str(w2v_fname))

if arg.w2v_show:
    w2v_show(w2v)
    exit()

conf = cvm.MatcherConfig(w2v, arg.max_score, arg.levenstein_ins_cost, arg.levenstein_del_cost)

cve_ids = []
cve_ids += arg.cve

with cvm.Database(arg.db) as db:
    if arg.cve_list:
        cve_show(db)
        exit()

    if arg.cwe_list:
        cwe_show(db)
        exit()

    if not arg.files:
        print('No source files specified', file=sys.stderr)
        exit(1)

    if arg.cwe:
        for cwe_id in arg.cwe:
            cve_ids += db.get_cves_by_cwe(cwe_id)

    if cve_ids:
        cves = [cve for cve_id in cve_ids for cve in get_cve(db, cve_id, arg.min_hunk_tokens)]
    else:
        print('No CVEs specified. Default to all C/C++ CVE records')
        cves = get_cves(db, arg.min_hunk_tokens)

    if arg.ignore_file:
        with open(arg.ignore_file, 'r') as f:
            for i in f:
                arg.ignore.append(i.strip())
    if arg.ignore:
        cve_ignore = set(i for i in arg.ignore if i.startswith('CVE'))
        cwe_ignore = set(i for i in arg.ignore if i.startswith('CWE'))
        id_ignore = set(i for i in arg.ignore if i.isdigit())
        cves = [i for i in cves if i.change_id not in id_ignore and i.cve_id not in cve_ignore and i.cwe_id not in cwe_ignore]

    if arg.split_diffs:
        cves = [i for cve in cves for i in cve.split()]

    if len(cves):
        if len(cves) < 100:
            print('Will check:')
            print(', '.join(set(i.cve_id for i in cves)))
            print(len(cves), 'file diffs in cves')
        else:
            print('Will check', len(cves), 'diffs')
    else:
        print('No CVEs to match', file=sys.stderr)
        exit(1)

    with cvm.Matcher(arg.files, cves, conf) as m:
        print(len(arg.files), 'files, max tokens in file: ', m.haystack_max)
        print('OpenCL search running on', ', '.join(i.name for i in m.lev.ctx.devices))
        for fname, ftokens in m.files:
            print('Processing', fname, 'tokens:', len(ftokens))
            for match in m.match(ftokens):
                for cve_rep in db.cve_report(match.cve.change_id):
                    print('Matched', cve_rep.cve_id, 'with score', '%0.6f' % match.dist_b, '- %0.6f' % match.dist_a)
                    if arg.report_diff_id:
                        print('Diff id:', match.cve.change_id)
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
                        for h in match.hunks:
                            print(f'{fname}:{tokens[h.start_token_ind]}:0   ', '%0.6f' % h.dist_b, '- %0.6f' % h.dist_a)
                            if arg.report_diff:
                                print(h.hunk.src)
                    print('')
