from gensim.models.keyedvectors import KeyedVectors
import numpy as np

class LevensteinSearch:
    '''Search for a position in haystack with minimal Levenstein distance to needle
       Levenstein distance is computed using words/tokens where common definition of Levenstein distance would use a char.
       Substitution cost is word2vec distance between tokens, not 1.'''

    def __init__(self, w2v:KeyedVectors, max_distance, insertion_cost=1, deletion_cost=1, default_distance=1):
        self.max_distance = max_distance
        self.insertion_cost = insertion_cost
        self.deletion_cost = deletion_cost
        self.default_distance = default_distance
        self.w2v = w2v
        self.__dist_cache = dict()

    def item_distance(self, a, b):
        if a == b:
            return 0
        key = a,b
        if (r := self.__dist_cache.get(key)) is None:
            try:
                r = self.w2v.distance(a,b)
            except KeyError:
                r = self.default_distance
            self.__dist_cache[key] = r # cache size is not limited, beware of OOM
        return r

    def distance(self, needle, haystack):
        m = len(needle)
        n = len(haystack)
        if n < m:
            return self.max_distance, len(needle)

        v0 = np.zeros(n + 1)
        v1 = np.zeros(n + 1)

        for i in range(m):
            v1[0] = i + 1

            for j in range(n):
                del_cost = v0[j + 1] + self.deletion_cost
                ins_cost = v1[j] + self.insertion_cost
                sub_cost = v0[j] + self.item_distance(needle[i], haystack[j])
                v1[j + 1] = min(del_cost, ins_cost, sub_cost)
            v0, v1 = v1, v0

        ind = np.argmin(v0)
        dist = v0[ind]
        return dist, ind
