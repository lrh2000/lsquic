/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * perf_server.c -- Implements the "perf" server, see
 *      https://tools.ietf.org/html/draft-banks-quic-performance-00
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#include <fcntl.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "../src/liblsquic/lsquic_hash.h"
#include "test_cert.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_byteswap.h"
#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_xperf.h"

#include "../xperf/xperf_monitor.h"
#include "../xperf/xperf_quic.h"


static lsquic_conn_ctx_t *
perf_server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    LSQ_INFO("New connection!");
    return NULL;
}


static void
perf_server_on_conn_closed (lsquic_conn_t *conn)
{
    LSQ_INFO("Connection closed");
}


struct lsquic_stream_ctx
{
    union {
        uint64_t        left;   /* Number of bytes left to write */
        unsigned char   buf[sizeof(uint64_t)];  /* Read client header in */
    }                   u;
    unsigned            n_h_read;   /* Number of header bytes read in */
};


struct lsquic_monitor_ctx
{
    struct xperf_monitor *monitor;
    struct event         *event;
};


static struct lsquic_stream_ctx *
perf_server_on_new_stream (void *unused, struct lsquic_stream *stream)
{
    struct lsquic_stream_ctx *stream_ctx;

    stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (stream_ctx)
    {
        lsquic_stream_wantread(stream, 1);
        return stream_ctx;
    }
    else
    {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
}


static size_t
perf_read_and_discard (void *user_data, const unsigned char *buf,
                                                        size_t count, int fin)
{
    return count;
}


static void
perf_server_on_read (struct lsquic_stream *stream,
                                        struct lsquic_stream_ctx *stream_ctx)
{
    ssize_t nr;
    size_t toread;

    if (stream_ctx->n_h_read < sizeof(stream_ctx->u.buf))
    {
        /* Read the header */
        toread = sizeof(stream_ctx->u.buf) - stream_ctx->n_h_read;
        nr = lsquic_stream_read(stream, stream_ctx->u.buf
                            + sizeof(stream_ctx->u.buf) - toread, toread);
        if (nr > 0)
        {
            stream_ctx->n_h_read += nr;
            if (stream_ctx->n_h_read == sizeof(stream_ctx->u.left))
            {
#if __BYTE_ORDER == __LITTLE_ENDIAN
                stream_ctx->u.left = bswap_64(stream_ctx->u.left);
#endif
                LSQ_INFO("client requests %"PRIu64" bytes on stream %"PRIu64,
                    stream_ctx->u.left, lsquic_stream_id(stream));
            }
        }
        else if (nr < 0)
        {
            LSQ_WARN("error reading from stream: %s", strerror(errno));
            lsquic_stream_close(stream);
        }
        else
        {
            LSQ_WARN("incomplete header on stream %"PRIu64", abort connection",
                lsquic_stream_id(stream));
            lsquic_stream_wantread(stream, 0);
            lsquic_conn_abort(lsquic_stream_conn(stream));
        }
    }
    else
    {
        /* Read up until FIN, discarding whatever the client is sending */
        nr = lsquic_stream_readf(stream, perf_read_and_discard, NULL);
        if (nr == 0)
        {
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_wantwrite(stream, 1);
        }
        else if (nr < 0)
        {
            LSQ_WARN("error reading from stream: %s", strerror(errno));
            lsquic_stream_close(stream);
        }
    }
}


static size_t
buffer_size (void *lsqr_ctx)
{
    struct lsquic_stream_ctx *const stream_ctx = lsqr_ctx;
    return stream_ctx->u.left;
}


static size_t
buffer_read (void *lsqr_ctx, void *buf, size_t count)
{
    struct lsquic_stream_ctx *const stream_ctx = lsqr_ctx;
    size_t left;

    left = buffer_size(stream_ctx);
    if (count > left)
        count = left;
    memset(buf, 0, count);
    stream_ctx->u.left -= count;
    return count;
}


static ssize_t
perf_stream_write_chunks(struct lsquic_stream *stream)
{
    struct lsquic_xperf_chunk *chunk;
    size_t chunk_size, chunk_offset;
    ssize_t written_size, total_written_size;

    total_written_size = 0;
    do {
        chunk = STAILQ_FIRST(&g_xperf_state->chunks);
        chunk_size = chunk->chunk[0].size;
        chunk_offset = g_xperf_state->data_off;

        written_size = lsquic_stream_write(stream, (void *)&chunk->chunk[0] + chunk_offset, chunk_size - chunk_offset);
        if (written_size < 0)
            return written_size;
        total_written_size += written_size;
        if ((size_t)written_size != chunk_size - chunk_offset)
        {
            g_xperf_state->data_off += written_size;
            break;
        }

        STAILQ_REMOVE_HEAD(&g_xperf_state->chunks, next);
        free(chunk);
        g_xperf_state->data_off = 0;
    } while (!STAILQ_EMPTY(&g_xperf_state->chunks));

    return total_written_size;
}


static void
perf_server_on_write (struct lsquic_stream *stream,
                                        struct lsquic_stream_ctx *stream_ctx)
{
    struct lsquic_reader reader;
    ssize_t nw;

    if (!g_xperf_state || STAILQ_EMPTY(&g_xperf_state->chunks))
    {
        reader = (struct lsquic_reader) { buffer_read, buffer_size, stream_ctx, };
        nw = lsquic_stream_writef(stream, &reader);
    }
    else
    {
        nw = perf_stream_write_chunks(stream);
    }

    if (nw >= 0)
        LSQ_DEBUG("%s: wrote %zd bytes", __func__, nw);
    else
        LSQ_WARN("%s: cannot write to stream: %s", __func__, strerror(errno));

    if (stream_ctx->u.left == 0)
        lsquic_stream_shutdown(stream, 1);
}


static void
perf_server_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx)
{
    LSQ_DEBUG("stream closed");
    free(stream_ctx);
}


static int64_t
calculate_clock_offset (void)
{
    struct timespec tp, wall_tp;
    uint64_t ts, wall_ts;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
    {
        LSQ_ERROR("calculate_clock_offset: clock_gettime(MONOTONIC): %s", strerror(errno));
        return 0;
    }

    if (clock_gettime(CLOCK_REALTIME, &wall_tp) < 0)
    {
        LSQ_ERROR("calculate_clock_offset: clock_gettime(REALTIME): %s", strerror(errno));
        return 0;
    }

    ts = (uint64_t)tp.tv_sec * 1000000 + tp.tv_nsec / 1000;
    wall_ts = (uint64_t)wall_tp.tv_sec * 1000000 + wall_tp.tv_nsec / 1000;

    return wall_ts - ts;
}


static struct lsquic_xperf_state *
perf_xperf_state_create (const char *dirname)
{
    struct lsquic_xperf_state *state;
    int dirfd, fd_qdat, fd_qack;
    FILE *fp_qdat, *fp_qack;

    dirfd = dirname ? open(dirname, __O_PATH) : AT_FDCWD;
    if (dirname && dirfd < 0)
    {
        LSQ_ERROR("perf_xperf_state_create: open(%s): %s\n",
              dirname, strerror(errno));
        return NULL;
    }

    fd_qdat = openat(dirfd, XPERF_QUIC_DATA_NAME, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_qdat < 0)
    {
        LSQ_ERROR("perf_xperf_state_create: openat(%s): %s\n",
              XPERF_QUIC_DATA_NAME, strerror(errno));
        close(dirfd);
        return NULL;
    }

    fd_qack = openat(dirfd, XPERF_QUIC_ACK_NAME, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_qack < 0)
    {
        LSQ_ERROR("perf_xperf_state_create: openat(%s): %s\n",
              XPERF_QUIC_ACK_NAME, strerror(errno));
        close(fd_qdat);
        return NULL;
    }

    close(dirfd);

    fp_qdat = fdopen(fd_qdat, "w");
    if (!fp_qdat)
    {
        LSQ_ERROR("perf_xperf_state_create: fdopen(%s): %s\n",
              XPERF_QUIC_DATA_NAME, strerror(errno));
        close(fd_qdat);
        close(fd_qack);
        return NULL;
    }

    fp_qack = fdopen(fd_qack, "w");
    if (!fp_qack)
    {
        LSQ_ERROR("perf_xperf_state_create: fdopen(%s): %s\n",
              XPERF_QUIC_ACK_NAME, strerror(errno));
        close(fd_qack);
        fclose(fp_qdat);
        return NULL;
    }

    state = malloc(sizeof(struct lsquic_xperf_state));
    if (!state)
    {
        LSQ_ERROR("perf_xperf_state_create: malloc: Out of memory");
        fclose(fp_qdat);
        fclose(fp_qack);
        return NULL;
    }

    STAILQ_INIT(&state->chunks);

    state->data_off = 0;
    if ((state->stamp_off = calculate_clock_offset()) == 0)
    {
        fclose(fp_qdat);
        fclose(fp_qack);
        free(state);
        return NULL;
    }

    state->fp_qdat = fp_qdat;
    state->fp_qack = fp_qack;

    return state;
}


static void
perf_xperf_state_destory (struct lsquic_xperf_state *state)
{
    fclose(state->fp_qdat);
    fclose(state->fp_qack);

    free(state);
}


static ssize_t
perf_xperf_emit_chunk (void *ctx, const void *data, size_t len)
{
    struct lsquic_xperf_chunk *chunk;

    chunk = (void *)data - sizeof(struct lsquic_xperf_chunk);
    assert(chunk->chunk[0].size == len);

    STAILQ_INSERT_TAIL(&g_xperf_state->chunks, chunk, next);

    return len;
}


static void
perf_xperf_monitor_cb (evutil_socket_t fd, short what, void *ctx_)
{
    struct lsquic_monitor_ctx *ctx;

    ctx = (struct lsquic_monitor_ctx *)ctx_;

    if (xperf_monitor_process(ctx->monitor) > 0)
        event_add(ctx->event, NULL);
}


static void *
perf_xperf_alloc (size_t len)
{
    void *base;
    base = malloc(len + sizeof(struct lsquic_xperf_chunk));
    return base + sizeof(struct lsquic_xperf_chunk);
}


const struct lsquic_stream_if perf_server_stream_if = {
    .on_new_conn            = perf_server_on_new_conn,
    .on_conn_closed         = perf_server_on_conn_closed,
    .on_new_stream          = perf_server_on_new_stream,
    .on_read                = perf_server_on_read,
    .on_write               = perf_server_on_write,
    .on_close               = perf_server_on_close,
};


static void
usage (const char *prog)
{
    const char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    printf(
"Usage: %s [opts] [FILES...]\n"
"\n"
"Options:\n"
"   FILES...    Transfer FILES into clients while running performance tests\n"
"   -d DIR      Log internal BBR indicators into files located at DIR.  If\n"
"                 not specified, use the current working directory.\n"
                , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct sport_head sports;
    struct lsquic_monitor_ctx mctx;
    const char *dirname;

    TAILQ_INIT(&sports);
    prog_init(&prog, LSENG_SERVER, &sports, &perf_server_stream_if, NULL);

    dirname = NULL;
    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "hd:")))
    {
        switch (opt) {
        case 'd':
            dirname = optarg;
            break;
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
    }

    g_xperf_state = perf_xperf_state_create(dirname);
    if (!g_xperf_state)
        exit(EXIT_FAILURE);

    mctx.monitor = xperf_monitor_create(O_NONBLOCK, (const char **)&argv[optind],
                                        argc - optind, &perf_xperf_emit_chunk,
                                        NULL, &perf_xperf_alloc);
    if (!mctx.monitor)
    {
        perf_xperf_state_destory(g_xperf_state);
        exit(EXIT_FAILURE);
    }

    add_alpn("perf");
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        xperf_monitor_destory(mctx.monitor);
        perf_xperf_state_destory(g_xperf_state);
        exit(EXIT_FAILURE);
    }

    mctx.event = event_new(prog_eb(&prog), mctx.monitor->watch_fd,
                           EV_READ, &perf_xperf_monitor_cb, &mctx);
    if (!mctx.event)
    {
        LSQ_ERROR("could not create ev");
        prog_cleanup(&prog);
        xperf_monitor_destory(mctx.monitor);
        perf_xperf_state_destory(g_xperf_state);
        exit(EXIT_FAILURE);
    }
    event_add(mctx.event, NULL);

    xperf_monitor_init(mctx.monitor);

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);
    prog_cleanup(&prog);

    event_del(mctx.event);
    event_free(mctx.event);
    xperf_monitor_destory(mctx.monitor);
    perf_xperf_state_destory(g_xperf_state);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
