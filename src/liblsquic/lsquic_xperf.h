#pragma once

#include <stdio.h>
#include <stdint.h>
#include <sys/queue.h>

#include "../../xperf/xperf_kern.h"

struct lsquic_xperf_chunk
{
    STAILQ_ENTRY(lsquic_xperf_chunk) next;
    struct xperf_chunk               chunk[0];
};

struct lsquic_xperf_state
{
    STAILQ_HEAD(, lsquic_xperf_chunk) chunks;
    size_t                            data_off;
    int64_t                           stamp_off;
    FILE                             *fp_qdat;
    FILE                             *fp_qack;
};

extern struct lsquic_xperf_state *g_xperf_state;
