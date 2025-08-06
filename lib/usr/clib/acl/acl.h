/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2025 Intel Corporation
 */

#ifndef _ACL_H_
#define _ACL_H_

/**
 * @file
 * ACL support for x86 archs. Routines to build and search an ACL table.
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CNE_ACL_QUAD_MAX    5
#define CNE_ACL_QUAD_SIZE   4
#define CNE_ACL_QUAD_SINGLE UINT64_C(0x7f7f7f7f00000000)

#define CNE_ACL_SINGLE_TRIE_SIZE 2000

#define CNE_ACL_DFA_MAX  UINT8_MAX
#define CNE_ACL_DFA_SIZE (UINT8_MAX + 1)

#define CNE_ACL_DFA_GR64_SIZE 64
#define CNE_ACL_DFA_GR64_NUM  (CNE_ACL_DFA_SIZE / CNE_ACL_DFA_GR64_SIZE)
#define CNE_ACL_DFA_GR64_BIT  (CHAR_BIT * sizeof(uint32_t) / CNE_ACL_DFA_GR64_NUM)

typedef int bits_t;

#define CNE_ACL_BIT_SET_SIZE ((UINT8_MAX + 1) / (sizeof(bits_t) * CHAR_BIT))

struct cne_acl_bitset {
    bits_t bits[CNE_ACL_BIT_SET_SIZE];
};

#define CNE_ACL_NODE_DFA    (0 << CNE_ACL_TYPE_SHIFT)
#define CNE_ACL_NODE_SINGLE (1U << CNE_ACL_TYPE_SHIFT)
#define CNE_ACL_NODE_QRANGE (3U << CNE_ACL_TYPE_SHIFT)
#define CNE_ACL_NODE_MATCH  (4U << CNE_ACL_TYPE_SHIFT)
#define CNE_ACL_NODE_TYPE   (7U << CNE_ACL_TYPE_SHIFT)
/*
 * Each ACL RT contains an idle nomatch node:
 * a SINGLE node at predefined position (CNE_ACL_DFA_SIZE)
 * that points to itself.
 */
#define CNE_ACL_IDLE_NODE (CNE_ACL_DFA_SIZE | CNE_ACL_NODE_SINGLE)

#define CNE_ACL_NODE_UNDEFINED UINT32_MAX

/*
 * ACL RT structure is a set of multibit tries (with stride == 8)
 * represented by an array of transitions. The next position is calculated
 * based on the current position and the input byte.
 * Each transition is 64 bit value with the following format:
 * | node_type_specific : 32 | node_type : 3 | node_addr : 29 |
 * For all node types except CNE_ACL_NODE_MATCH, node_addr is an index
 * to the start of the node in the transitions array.
 * Few different node types are used:
 * CNE_ACL_NODE_MATCH:
 * node_addr value is and index into an array that contains the return value
 * and its priority for each category.
 * Upper 32 bits of the transition value are not used for that node type.
 * CNE_ACL_NODE_QRANGE:
 * that node consist of up to 5 transitions.
 * Upper 32 bits are interpreted as 4 signed character values which
 * are ordered from smallest(INT8_MIN) to largest (INT8_MAX).
 * These values define 5 ranges:
 * INT8_MIN <= range[0]  <= ((int8_t *)&transition)[4]
 * ((int8_t *)&transition)[4] < range[1] <= ((int8_t *)&transition)[5]
 * ((int8_t *)&transition)[5] < range[2] <= ((int8_t *)&transition)[6]
 * ((int8_t *)&transition)[6] < range[3] <= ((int8_t *)&transition)[7]
 * ((int8_t *)&transition)[7] < range[4] <= INT8_MAX
 * So for input byte value within range[i] i-th transition within that node
 * will be used.
 * CNE_ACL_NODE_SINGLE:
 * always transitions to the same node regardless of the input value.
 * CNE_ACL_NODE_DFA:
 * that node consists of up to 256 transitions.
 * In attempt to conserve space all transitions are divided into 4 consecutive
 * groups, by 64 transitions per group:
 * group64[i] contains transitions[i * 64, .. i * 64 + 63].
 * Upper 32 bits are interpreted as 4 unsigned character values one per group,
 * which contain index to the start of the given group within the node.
 * So to calculate transition index within the node for given input byte value:
 * input_byte - ((uint8_t *)&transition)[4 + input_byte / 64].
 */

/*
 * Structure of a node is a set of ptrs and each ptr has a bit map
 * of values associated with this transition.
 */
struct cne_acl_ptr_set {
    struct cne_acl_bitset values; /* input values associated with ptr */
    struct cne_acl_node *ptr;     /* transition to next node */
};

struct cne_acl_classifier_results {
    int results[CNE_ACL_MAX_CATEGORIES];
};

struct cne_acl_match_results {
    uint32_t results[CNE_ACL_MAX_CATEGORIES];
    int32_t priority[CNE_ACL_MAX_CATEGORIES];
};

struct cne_acl_node {
    uint64_t node_index; /* index for this node */
    uint32_t level;      /* level 0-n in the trie */
    uint32_t ref_count;  /* ref count for this node */
    struct cne_acl_bitset values;
    /* set of all values that map to another node
     * (union of bits in each transition.
     */
    uint32_t num_ptrs;            /* number of ptr_set in use */
    uint32_t max_ptrs;            /* number of allocated ptr_set */
    uint32_t min_add;             /* number of ptr_set per allocation */
    struct cne_acl_ptr_set *ptrs; /* transitions array for this node */
    int32_t match_flag;
    int32_t match_index; /* index to match data */
    uint32_t node_type;
    int32_t fanout;
    /* number of ranges (transitions w/ consecutive bits) */
    int32_t id;
    struct cne_acl_match_results *mrt; /* only valid when match_flag != 0 */
    union {
        char transitions[CNE_ACL_QUAD_SIZE];
        /* boundaries for ranged node */
        uint8_t dfa_gr64[CNE_ACL_DFA_GR64_NUM];
    };
    struct cne_acl_node *next;
    /* free list link or pointer to duplicate node during merge */
    struct cne_acl_node *prev;
    /* points to node from which this node was duplicated */
};

/*
 * Types of tries used to generate runtime structure(s)
 */
enum {
    CNE_ACL_FULL_TRIE    = 0,
    CNE_ACL_NOSRC_TRIE   = 1,
    CNE_ACL_NODST_TRIE   = 2,
    CNE_ACL_NOPORTS_TRIE = 4,
    CNE_ACL_NOVLAN_TRIE  = 8,
    CNE_ACL_UNUSED_TRIE  = 0x80000000
};

/** MAX number of tries per one ACL context.*/
#define CNE_ACL_MAX_TRIES 8

/** Max number of characters in PM name.*/
#define CNE_ACL_NAMESIZE 32

struct cne_acl_trie {
    uint32_t type;
    uint32_t count;
    uint32_t root_index;
    const uint32_t *data_index;
    uint32_t num_data_indexes;
};

struct cne_acl_bld_trie {
    struct cne_acl_node *trie;
};

struct cne_acl_ctx {
    char name[CNE_ACL_NAMESIZE];
    /** Name of the ACL context. */
    enum cne_acl_classify_alg alg;
    uint32_t first_load_sz;
    void *rules;
    uint32_t max_rules;
    uint32_t rule_sz;
    uint32_t num_rules;
    uint32_t num_categories;
    uint32_t num_tries;
    uint32_t match_index;
    uint64_t no_match;
    uint64_t idle;
    uint64_t *trans_table;
    uint32_t *data_indexes;
    struct cne_acl_trie trie[CNE_ACL_MAX_TRIES];
    void *mem;
    size_t mem_sz;
    struct cne_acl_config config; /* copy of build config. */
};

int cne_acl_gen(struct cne_acl_ctx *ctx, struct cne_acl_trie *trie,
                struct cne_acl_bld_trie *node_bld_trie, uint32_t num_tries, uint32_t num_categories,
                uint32_t data_index_sz, size_t max_size);

typedef int (*cne_acl_classify_t)(const struct cne_acl_ctx *, const uint8_t **, uint32_t *,
                                  uint32_t, uint32_t);

/*
 * Different implementations of ACL classify.
 */
int cne_acl_classify_scalar(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                            uint32_t num, uint32_t categories);

int cne_acl_classify_sse(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                         uint32_t num, uint32_t categories);

int cne_acl_classify_avx2(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                          uint32_t num, uint32_t categories);

int cne_acl_classify_avx512x16(const struct cne_acl_ctx *ctx, const uint8_t **data,
                               uint32_t *results, uint32_t num, uint32_t categories);

int cne_acl_classify_avx512x32(const struct cne_acl_ctx *ctx, const uint8_t **data,
                               uint32_t *results, uint32_t num, uint32_t categories);

int cne_acl_classify_neon(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                          uint32_t num, uint32_t categories);

int cne_acl_classify_altivec(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                             uint32_t num, uint32_t categories);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _ACL_H_ */
