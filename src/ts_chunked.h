
#ifndef _TS_CHUNKED_H
#define _TS_CHUNKED_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ts/ts.h>
#include <ts/experimental.h>


typedef enum {
    TS_DECHUNK_WAIT_LENGTH = 0,
    TS_DECHUNK_WAIT_RETURN,
    TS_DECHUNK_WAIT_DATA,
    TS_DECHUNK_WAIT_RETURN_END,
    TS_DECHUNK_DATA_DONE,
} ts_dechunk_state;

typedef struct {
    int             state;

    int             frag_total;
    int             frag_len;
    char            frag_buf[16];
    unsigned char   frag_pos;

    int             done:1;
    int             cr:1;
    int             dechunk_enabled:1;
} ts_dechunk_info;

typedef struct {
    TSVIO               output_vio;
    TSIOBuffer          output_buffer;
    TSIOBufferReader    output_reader;

    int64_t             total;
} ts_chunked_transform_ctx;

typedef struct {
    ts_dechunk_info     *info;
    TSVIO               output_vio;
    TSIOBuffer          output_buffer;
    TSIOBufferReader    output_reader;

    int64_t             total;
} ts_dechunk_transform_ctx;



int ts_chunked_process(TSIOBufferReader readerp, TSIOBuffer bufp, int end);

ts_dechunk_info * ts_dechunk_info_create(int dechunk);
void ts_dechunk_info_destroy(ts_dechunk_info *info);

int ts_dechunk_process(ts_dechunk_info *info, TSIOBufferReader readerp, TSIOBuffer bufp, int end);

int ts_chunked_transform(TSHttpTxn txnp);
int ts_dechunk_transform(TSHttpTxn txnp);

#ifdef  __cplusplus
}
#endif

#endif

