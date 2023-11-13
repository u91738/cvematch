import unidiff
from typing import List, Optional
import itertools as it
from dataclasses import dataclass
from gensim.models.keyedvectors import KeyedVectors
from math import ceil
from .tokenize import tokenize
from .measure import LevensteinSearch

@dataclass
class CVEHunk:
    tokens:List[str]
    src:Optional[str] = None

@dataclass
class Match:
    weight:float
    position:int
    src:Optional[str]

@dataclass
class MatcherConfig:
    w2v:KeyedVectors
    max_score:float
    levenstein_ins_cost:float
    levenstein_del_cost:float

class CVEDesc:
    def __init__(self, conf:MatcherConfig, change_id:str, before:List[CVEHunk], after:List[CVEHunk]):
        self.change_id = change_id
        self.before = before
        self.after = after
        self.before_len = sum(len(i.tokens) for i in before)
        self.after_len = sum(len(i.tokens) for i in after)
        self.verbose = False
        self.conf = conf

    def dprint(self, *args):
        if self.verbose:
            print(*args)

    def from_patch(conf:MatcherConfig, change_id:str, diff:str):
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
            return CVEDesc(conf, change_id, before, after)
        else:
            return None

    def __match(self, changes, tokens, total_score_max):
        if len(changes) == 0 or len(tokens) == 0:
            return None, None

        lev = LevensteinSearch(
                    self.conf.w2v,
                    total_score_max * sum(len(i.tokens) for i in changes),
                    self.conf.levenstein_ins_cost,
                    self.conf.levenstein_del_cost)
        res = []
        weight = 0
        adjusted_weight = 0

        for hunk in changes:
            hunk_weight, hunk_end_node = lev.distance(hunk.tokens, tokens)

            weight += hunk_weight / len(hunk.tokens) # adjust score to hunk size
            adjusted_weight = weight / len(changes)
            res.append(Match(adjusted_weight, hunk_end_node - len(hunk.tokens), hunk.src))

            if adjusted_weight > total_score_max:
                return None, None

        return (adjusted_weight, res) if res else (None, None)

    def match_tokens(self, tokens: List[str]):
        score_b, path_b = self.__match(self.before, tokens, self.conf.max_score)
        if score_b is None:
            return None, None, None

        if score_b < self.conf.max_score:
            score_a, _ = self.__match(self.after, tokens, self.conf.max_score)
            self.dprint('match_tokens, score before fix:', score_b, 'after fix:', score_a)
            return path_b, score_b, score_a
        else:
            self.dprint('match_tokens, score before fix:', score_b)
            return None, None, None
