from collections import defaultdict
from typing import List, Optional
from dataclasses import dataclass
import unidiff
import numpy as np
from gensim.models.keyedvectors import KeyedVectors
from .tokenize import tokenize
from .measure import LevensteinSearchCL


@dataclass
class CVEHunk:
    tokens:List[str]
    src:Optional[str] = None


@dataclass
class MatcherConfig:
    w2v:KeyedVectors
    max_score:float
    levenstein_ins_cost:float
    levenstein_del_cost:float


class CVEDesc:
    '''File change in a CVE fix'''

    def __init__(self, change_id:str, cve_id:str, cwe_id:str, before:List[CVEHunk], after:List[CVEHunk]):
        self.change_id = change_id
        self.cve_id = cve_id
        self.cwe_id = cwe_id
        self.before = before
        self.after = after
        self.before_len = sum(len(i.tokens) for i in before)
        self.after_len = sum(len(i.tokens) for i in after)

    def from_patch(change_id:str, cve_id:str, cwe_id:str, diff:str, min_hunk_tokens):
        before = []
        after = []
        for patch in unidiff.PatchSet.from_string(diff):
            last_hunk_end_b, last_hunk_end_a = None, None
            for hunk in patch:
                hunk_before, hunk_after, hunk_src = [], [], []
                for line in hunk:
                    tokens = tokenize(line.value)
                    if line.is_context:
                        hunk_before += tokens
                        hunk_after += tokens
                        hunk_src.append(line.value)
                    elif line.is_added:
                        hunk_after += tokens
                        hunk_src.append('+' + line.value)
                    elif line.is_removed:
                        hunk_before += tokens
                        hunk_src.append('-' + line.value)
                dist_b = hunk.source_start - last_hunk_end_b if last_hunk_end_b else None
                dist_a = hunk.target_start - last_hunk_end_a if last_hunk_end_a else None
                src = ''.join(hunk_src)
                if len(hunk_before) >= min_hunk_tokens:
                    before.append(CVEHunk(hunk_before, src))
                    last_hunk_end_b = hunk.source_start + hunk.source_length
                if len(hunk_after) >= min_hunk_tokens:
                    after.append(CVEHunk(hunk_after))
                    last_hunk_end_a = hunk.target_start + hunk.target_length
        if before:
            return CVEDesc(change_id, cve_id, cwe_id, before, after)
        else:
            return None


@dataclass
class HunkMatch:
    start_token_ind: int
    hunk: CVEHunk
    dist_b: float
    dist_a: float

@dataclass
class CveMatch:
    cve: CVEDesc
    hunks: List[HunkMatch]
    dist_b: float
    dist_a: float

def fix_neg_zero(f:float):
    '''floats are fun, pretend that (-1e-6 ... 1e-6) is 0.0'''
    return 0.0 if abs(f) < 1e-6 else f

def fix_neg_zeros(fs:List[float]):
    '''floats are fun, pretend that (-1e-6 ... 1e-6) is 0.0'''
    return [fix_neg_zero(i) for i in fs]

class Matcher:
    '''OpenCL matcher for CVE fixes'''

    def __init__(self, files, cves, conf):
        self.conf = conf
        self.needles_before_map = defaultdict(lambda: [])
        self.needles_before = []
        for cve in cves:
            for hunk in cve.before:
                self.needles_before_map[cve].append(len(self.needles_before))
                self.needles_before.append(hunk.tokens)

        self.files = []
        for fname in files:
            with open(fname, 'r') as f:
                self.files.append((fname, tokenize(f.read())))
        self.haystack_max = max(len(i[1]) for i in self.files)

        self.lev = LevensteinSearchCL(conf.w2v,
                                      self.haystack_max,
                                      conf.levenstein_ins_cost,
                                      conf.levenstein_del_cost,
                                      1)
        self.needles_b = self.lev.prepare_needles(self.needles_before)

        self.haystack = self.lev.prepare_haystack()

    def __enter__(self):
        self.needles_b.__enter__()
        self.lev.__enter__()
        self.haystack.__enter__()
        return self

    def __exit__(self, t, v, bt):
        self.needles_b.__exit__(t, v, bt)
        self.lev.__exit__(t, v, bt)
        self.haystack.__exit__(t, v, bt)

    def match(self, haystack_tokens) -> List[CveMatch]:
        self.haystack.assign(haystack_tokens)

        # match with CVEs before fix
        dist_b, ind = self.lev.search(self.needles_b, self.haystack)

        # gather cve's that scored below limit
        scores_b = dict()
        for cve, hunk_inds in self.needles_before_map.items():
            raw_scores = dist_b[hunk_inds]
            score_b = np.mean(raw_scores)
            if score_b < self.conf.max_score:
                scores_b[cve] = score_b, raw_scores

        if len(scores_b) == 0:
            return []

        # prepare CVEs after fix for CVEs that scored low enough
        needles_after_map = defaultdict(lambda: [])
        needles_after = []
        for cve in scores_b.keys():
            for hunk in cve.after:
                needles_after_map[cve].append(len(needles_after))
                needles_after.append(hunk.tokens)

        # match with CVEs after fix
        with self.lev.prepare_needles(needles_after) as needles_a:
            dist_a, _ = self.lev.search(needles_a, self.haystack)

        res = []
        for cve, (score_b, raw_scores_b) in scores_b.items():
            raw_scores_a = dist_a[needles_after_map[cve]]
            score_a = np.mean(raw_scores_a)
            # if file is more similar to state before fix than after fix - gather results
            if score_b < score_a:
                score_b = fix_neg_zero(score_b)
                score_a = fix_neg_zero(score_a)

                assert score_b >= 0 and score_a >= 0

                matches = [HunkMatch(i, hunk, db, da)
                            for i, hunk, db, da in
                                zip(ind[self.needles_before_map[cve]],
                                    cve.before,
                                    fix_neg_zeros(raw_scores_b),
                                    fix_neg_zeros(raw_scores_a))]
                res.append(CveMatch(cve, matches, score_b, score_a))
        return res
