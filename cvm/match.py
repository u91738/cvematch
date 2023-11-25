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
    def __init__(self, change_id:str, before:List[CVEHunk], after:List[CVEHunk]):
        self.change_id = change_id
        self.before = before
        self.after = after
        self.before_len = sum(len(i.tokens) for i in before)
        self.after_len = sum(len(i.tokens) for i in after)

    def from_patch(change_id:str, diff:str):
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
                if hunk_before:
                    before.append(CVEHunk(hunk_before, src))
                    last_hunk_end_b = hunk.source_start + hunk.source_length
                if hunk_after:
                    after.append(CVEHunk(hunk_after))
                    last_hunk_end_a = hunk.target_start + hunk.target_length
        if before:
            return CVEDesc(change_id, before, after)
        else:
            return None


@dataclass
class HunkMatch:
    start_token_ind: int
    hunk: CVEHunk
    dist_b: float


class Matcher:
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

    def match(self, haystack_tokens):
        self.haystack.assign(haystack_tokens)

        # match with CVEs before fix
        dist_b, ind = self.lev.search(self.needles_b, self.haystack)

        # gather cve's that scored below limit
        scores_b = dict()
        for cve, hunk_inds in self.needles_before_map.items():
            score_b = np.mean(dist_b[hunk_inds])
            if score_b < self.conf.max_score:
                scores_b[cve] = score_b

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
        for cve, score_b in scores_b.items():
            score_a = np.mean(dist_a[needles_after_map[cve]])
            # if file is more similar to state before fix than after fix - gather results
            if score_b < score_a:
                matches = [HunkMatch(i, hunk, db) for i, hunk, db in zip(ind[hunk_inds], cve.before, dist_b[hunk_inds])]
                res.append((score_b, score_a, matches, cve))
        return res
