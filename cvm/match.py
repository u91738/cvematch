import unidiff
from typing import List, Optional
from dataclasses import dataclass
from gensim.models.keyedvectors import KeyedVectors
from .tokenize import tokenize


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
