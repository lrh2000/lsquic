/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_frame_reader.h -- Read HTTP frames from stream
 */

#ifndef LSQUIC_FRAME_READER_H
#define LSQUIC_FRAME_READER_H 1

#include <stddef.h>
#include <stdint.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

struct lshpack_dec;
struct lsquic_mm;
struct lsquic_stream;
struct lsquic_frame_reader;
struct lsquic_hset_if;
struct uncompressed_headers;


enum frame_reader_flags
{
    FRF_SERVER      = (1 << 0),
    FRF_HAVE_PREV   = (1 << 1),
};


/* Frame reader may hit some error conditions which are reported using
 * callback fc_on_error.  These codes are later mapped stream- or
 * connection-level errors.
 */
enum frame_reader_error
{
    FR_ERR_DUPLICATE_PSEH     =  LSQUIC_HDR_ERR_DUPLICATE_PSDO_HDR,
    FR_ERR_INCOMPL_REQ_PSEH   =  LSQUIC_HDR_ERR_INCOMPL_REQ_PSDO_HDR,
    FR_ERR_UNNEC_REQ_PSEH     =  LSQUIC_HDR_ERR_UNNEC_REQ_PSDO_HDR,
    FR_ERR_INCOMPL_RESP_PSEH  =  LSQUIC_HDR_ERR_INCOMPL_RESP_PSDO_HDR,
    FR_ERR_UNNEC_RESP_PSEH    =  LSQUIC_HDR_ERR_UNNEC_RESP_PSDO_HDR,
    FR_ERR_UNKNOWN_PSEH       =  LSQUIC_HDR_ERR_UNKNOWN_PSDO_HDR,
    FR_ERR_UPPERCASE_HEADER   =  LSQUIC_HDR_ERR_UPPERCASE_HEADER,
    FR_ERR_MISPLACED_PSEH     =  LSQUIC_HDR_ERR_MISPLACED_PSDO_HDR,
    FR_ERR_MISSING_PSEH       =  LSQUIC_HDR_ERR_MISSING_PSDO_HDR,
    FR_ERR_HEADERS_TOO_LARGE  =  LSQUIC_HDR_ERR_HEADERS_TOO_LARGE,
    FR_ERR_NOMEM              =  LSQUIC_HDR_ERR_NOMEM,

    FR_ERR_DECOMPRESS,
    FR_ERR_INVALID_FRAME_SIZE,  /* E.g. a SETTINGS frame length is not a multiple
                                 * of 6 (RFC 7540, Section 6.5.1).
                                 */
    FR_ERR_NONZERO_STREAM_ID,
    FR_ERR_ZERO_STREAM_ID,
    FR_ERR_SELF_DEP_STREAM,     /* A stream in priority frame cannot depend on
                                 * itself (RFC 7540, Section 5.3.1).
                                 */
    FR_ERR_UNEXPECTED_PUSH,
    FR_ERR_EXPECTED_CONTIN,     /* Expected continuation frame. */
};


struct frame_reader_callbacks
{
    void (*frc_on_headers)      (void *frame_cb_ctx, struct uncompressed_headers *);
    void (*frc_on_push_promise) (void *frame_cb_ctx, struct uncompressed_headers *);
    void (*frc_on_settings)     (void *frame_cb_ctx, uint16_t setting_id,
                                 uint32_t setting_value);
    void (*frc_on_priority)     (void *frame_cb_ctx, uint32_t stream_id,
                                 int exclusive, uint32_t dep_stream_id,
                                 unsigned weight);
    void (*frc_on_error)        (void *frame_cb_ctx, uint32_t stream_id,
                                 enum frame_reader_error);
};

typedef ssize_t (*fr_stream_read_f)(struct lsquic_stream *, void *, size_t);

struct lsquic_frame_reader *
lsquic_frame_reader_new (enum frame_reader_flags, unsigned max_headers_sz,
                         struct lsquic_mm *, struct lsquic_stream *,
                         fr_stream_read_f, struct lshpack_dec *,
                         const struct frame_reader_callbacks *, void *fr_cb_ctx,
                         const struct lsquic_hset_if *, void *hsi_ctx);

int
lsquic_frame_reader_read (struct lsquic_frame_reader *);

void
lsquic_frame_reader_destroy (struct lsquic_frame_reader *);

size_t
lsquic_frame_reader_mem_used (const struct lsquic_frame_reader *);

#endif
