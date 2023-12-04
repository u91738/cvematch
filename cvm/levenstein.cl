/*
OpenCL implementation of search for position
where subsequence has minimal distance to a sequence.

Distance is a Levenstein distance modification where
- items for deletion/insertion/substitution are words, not characters
- words are represented as word2vec vectors
- substitution cost is cosine distance between these vectors

Cosine distance goes from 0 to 2, so default insertion and deletion costs are 2
*/

#ifndef DEL_COST
#define DEL_COST 2
#endif

#ifndef INS_COST
#define INS_COST 2
#endif

#ifndef DEFAULT_DISTANCE
#define DEFAULT_DISTANCE 1
#endif

#ifndef HAYSTACK_MAX
#define HAYSTACK_MAX 32768
#endif

#ifndef VECTOR_SIZE
#define VECTOR_SIZE 128
#endif

// bigger cache has very little preformance benefits
#ifndef CACHE_SIZE
#define CACHE_SIZE 10000
#endif


static inline float cosine_similarity(__constant const float *a, __constant const float *b) {
    float dot_product = 0;
    float a_sum = 0;
    float b_sum = 0;
    for(uint i = 0; i < VECTOR_SIZE; ++i) {
        float ai = a[i];
        float bi = b[i];
        dot_product += ai * bi;
        a_sum += ai * ai;
        b_sum += bi * bi;
    }
    return dot_product / (sqrt(a_sum) * sqrt(b_sum));
}


static inline float cosine_distance(__constant const float *a, __constant const float *b) {
    return 1 - cosine_similarity(a, b);
}


struct cache_record {
    int a;
    int b;
    float dist;
};
struct cache_record cache[CACHE_SIZE] = {};


static inline float item_distance(__constant const float *dictionary, int a, int b) {
    if(a == -1 || b == -1)
        return DEFAULT_DISTANCE;

    struct cache_record *c = cache + ((a+b) % CACHE_SIZE);
    if(c->a == a && c->b == b)
        return c->dist;

    float dist = cosine_distance(dictionary + a*VECTOR_SIZE, dictionary + b*VECTOR_SIZE);
    *c = (struct cache_record){a, b, dist};
    return dist;
}


static inline float min3(float a, float b, float c) {
    if (a <= b) {
        return a <= c ? a : c;
    } else {
        return b <= c ? b : c;
    }
}


/**
 * Find index of a minimal element
 */
static inline uint argmin(float *a, uint a_size) {
    uint r = 0;
    for(uint i = 0; i < a_size; ++i) {
        if(a[i] < a[r])
            r = i;
    }
    return r;
}


/**
 * Find index in haystack where needle has minimal distance to haystack.
 * Returns index and distance
 */
void levenstein_search(
    __constant const float *dictionary,
    __constant const int *needle, uint needle_size,
    __constant const int *haystack, uint haystack_size,
    __global float *dist,
    __global int *ind
) {
    if(haystack_size > HAYSTACK_MAX - 1) {
        printf("ERROR: haystack_size %u is over HAYSTACK_MAX %u\n", haystack_size, HAYSTACK_MAX);
        *ind = -1;
        *dist = INFINITY;
    } if (needle_size > haystack_size) {
        *ind = -1;
        *dist = INFINITY;
    } else {
        /*
            "matrix" levenstein distance algorithm that preserves only last 2 rows.
            To convert from distance computation to search
            set buffer to zeros instead of 1,2,3,4,...
            then return index of minimal value from v0.
        */
        float buf0[HAYSTACK_MAX] = {0};
        float buf1[HAYSTACK_MAX] = {0};
        float *v0 = buf0;
        float *v1 = buf1;
        float *tmp;

        for(uint i = 0; i < needle_size; ++i) {
            v1[0] = i + 1;

            for(uint j = 0; j < haystack_size; ++j) {
                float del_cost = v0[j + 1] + DEL_COST;
                float ins_cost = v1[j] + INS_COST;
                float sub_cost = v0[j] + item_distance(dictionary, needle[i], haystack[j]);
                v1[j + 1] = min3(del_cost, ins_cost, sub_cost);
            }
            tmp = v0;
            v0 = v1;
            v1 = tmp;
        }

        int i = argmin(v0, haystack_size + 1);

        *ind = i >= needle_size ? i - needle_size : 0;
        *dist = v0[i];
    }
}


/**
 * Find index in haystack where needle has minimal distance to haystack.
 * Returns index and distance / size of matched needle
 */
__kernel void levenstein_score_all_needles(
    __constant const float *dictionary, uint dictionary_size,
    __constant const int *needles, // each needle must start with size as zero element
    __constant const uint *needle_offsets, // offsets where each needle starts for fast indexing
    __constant const int *haystack, uint haystack_size,
    __global float *dist,
    __global int *ind
) {
    size_t id = get_global_id(0);
    size_t offset = needle_offsets[id];
    size_t needle_size = needles[offset];
    __constant const int *needle = needles + offset + 1;

    levenstein_search(dictionary,
                      needle, needle_size,
                      haystack, haystack_size,
                      dist + id,
                      ind + id);
    dist[id] /= needle_size;
}
