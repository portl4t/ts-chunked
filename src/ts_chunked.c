
#include "ts_chunked.h"

static int ts_dechunk_extract_frag_len(ts_dechunk_info *info, const char *start, int64_t n);
static int ts_dechunk_extract_return(ts_dechunk_info *info, const char *start, int64_t n, int tail);

static int ts_chunked_transform_entry(TSCont contp, TSEvent event, void *edata);
static int ts_dechunk_transform_entry(TSCont contp, TSEvent event, void *edata);
static void ts_chunked_destroy_transform_ctx(ts_chunked_transform_ctx *transform_ctx);
static void ts_dechunk_destroy_transform_ctx(ts_dechunk_transform_ctx *transform_ctx);

static int ts_chunked_transform_handler(TSCont contp, ts_chunked_transform_ctx *tc);
static int ts_dechunk_transform_handler(TSCont contp, ts_dechunk_transform_ctx *tc);


int
ts_chunked_process(TSIOBufferReader readerp, TSIOBuffer bufp, int end)
{
    char    hex[32];
    int     n;
    int64_t avail;

    avail = TSIOBufferReaderAvail(readerp);

    if (avail) {
        n = snprintf(hex, sizeof(hex), "%llx\r\n", (long long)avail);

        TSIOBufferWrite(bufp, hex, n);
        TSIOBufferCopy(bufp, readerp, avail, 0);
        TSIOBufferWrite(bufp, "\r\n", sizeof("\r\n") - 1);

        TSIOBufferReaderConsume(readerp, avail);
    }

    if (end)
        TSIOBufferWrite(bufp, "0\r\n\r\n", sizeof("0\r\n\r\n") - 1);

    return end;
}


ts_dechunk_info *
ts_dechunk_info_create(int flag)
{
    ts_dechunk_info *info = (ts_dechunk_info*)TSmalloc(sizeof(ts_dechunk_info));
    memset(info, 0, sizeof(ts_dechunk_info));
    info->dechunk_enabled = flag;

    return info;
}

void
ts_dechunk_info_destroy(ts_dechunk_info *info)
{
    TSfree(info);
}

int
ts_dechunk_process(ts_dechunk_info *info, TSIOBufferReader readerp, TSIOBuffer bufp, int end)
{
    int         n;
    int64_t     avail, need;
    int64_t     blk_len;
    const char  *start;
    const char  *cur;
    TSIOBufferBlock blk, next_blk;

    blk = TSIOBufferReaderStart(readerp);

    while (blk) {

        next_blk = TSIOBufferBlockNext(blk);

        start = TSIOBufferBlockReadStart(blk, readerp, &blk_len);
        avail = blk_len;

        if (avail) {

            do {
                cur = start + blk_len - avail;

                switch (info->state) {

                    case TS_DECHUNK_WAIT_LENGTH:
                        n = ts_dechunk_extract_frag_len(info, cur, avail);
                        if (n < 0)
                            return -1;

                        avail -= n;

                        if (!info->dechunk_enabled)
                            TSIOBufferCopy(bufp, readerp, n, 0);

                        TSIOBufferReaderConsume(readerp, n);
                        break;

                    case TS_DECHUNK_WAIT_RETURN:
                        n = ts_dechunk_extract_return(info, cur, avail, 0);
                        avail -= n;

                        if (!info->dechunk_enabled)
                            TSIOBufferCopy(bufp, readerp, n, 0);

                        TSIOBufferReaderConsume(readerp, n);
                        break;

                    case TS_DECHUNK_WAIT_DATA:
                        if (info->frag_len + avail <= info->frag_total) {
                            TSIOBufferCopy(bufp, readerp, avail, 0);
                            TSIOBufferReaderConsume(readerp, avail);
                            info->frag_len += avail;
                            avail = 0;
                            break;
                        } else {
                            need = info->frag_total - info->frag_len;
                            if (need) {
                                TSIOBufferCopy(bufp, readerp, need, 0);
                                TSIOBufferReaderConsume(readerp, need);
                                info->frag_len += need;
                                avail -= need;
                            }

                            info->cr = 0;
                            info->state = TS_DECHUNK_WAIT_RETURN_END;
                        }

                        break;

                    case TS_DECHUNK_WAIT_RETURN_END:
                        n = ts_dechunk_extract_return(info, cur, avail, 1);
                        avail -= n;

                        if (!info->dechunk_enabled)
                            TSIOBufferCopy(bufp, readerp, n, 0);

                        TSIOBufferReaderConsume(readerp, n);
                        break;

                    case TS_DECHUNK_DATA_DONE:

                        if (!info->dechunk_enabled)
                            TSIOBufferCopy(bufp, readerp, avail, 0);

                        TSIOBufferReaderConsume(readerp, avail);
                        avail = 0;
                        info->done = 1;
                        break;

                    default:
                        break;
                }
            } while (avail > 0);
        }

        if (info->done)
            break;

        blk = next_blk;
    }

    if (info->done) {
        return 1;

    } else if (end) {
        return -1;

    } else {
        return 0;
    }
}

static int
ts_dechunk_extract_frag_len(ts_dechunk_info *info, const char *start, int64_t n)
{
    const char *ptr = start;
    const char *end = start + n;

    while (ptr < end) {

        if ((*ptr >= '0' && *ptr <= '9') || (*ptr >= 'a' && *ptr <= 'f') || (*ptr >= 'A' && *ptr <= 'F')) {

            info->frag_buf[info->frag_pos++] = *ptr;

            if (info->frag_pos > sizeof(info->frag_buf) - 1)
                return -1;

            ptr++;

        } else {

            if (info->frag_pos == 0)
                return -1;

            info->frag_buf[info->frag_pos++] = 0;
            sscanf(info->frag_buf, "%x", &(info->frag_total));
            info->frag_len = 0;

            if (info->frag_total == 0) {
                info->state = TS_DECHUNK_DATA_DONE;

            } else {
                info->cr = 0;
                info->state = TS_DECHUNK_WAIT_RETURN;
            }

            break;
        }
    }

    return ptr - start;
}

static int
ts_dechunk_extract_return(ts_dechunk_info *info, const char *start, int64_t n, int tail)
{
    const char *ptr = start;
    const char *end = start + n;

    if (!n)
        return 0;

    do {
        if (info->cr && *ptr ++ == '\n') {

            if (tail) {
                info->frag_pos = 0;
                info->state = TS_DECHUNK_WAIT_LENGTH;

            } else {
                info->frag_len = 0;
                info->state = TS_DECHUNK_WAIT_DATA;
            }

            break;
        }

        ptr = (char*)memchr(ptr, '\r', end - ptr);
        if (ptr) {
            info->cr = 1;
            ptr++;
        }

    } while (ptr < end);

    return ptr - start;
}

int
ts_chunked_transform(TSHttpTxn txnp)
{
    TSVConn                     connp;
    ts_chunked_transform_ctx    *ctx;

    ctx = (ts_chunked_transform_ctx*)TSmalloc(sizeof(ts_chunked_transform_ctx));
    memset(ctx, 0, sizeof(ts_chunked_transform_ctx));

    connp = TSTransformCreate(ts_chunked_transform_entry, txnp);
    TSContDataSet(connp, ctx);
    TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
    return 0;
}

int
ts_dechunk_transform(TSHttpTxn txnp)
{
    TSVConn                     connp;
    ts_dechunk_transform_ctx    *ctx;

    ctx = (ts_dechunk_transform_ctx*)TSmalloc(sizeof(ts_dechunk_transform_ctx));
    memset(ctx, 0, sizeof(ts_chunked_transform_ctx));

    ctx->info = ts_dechunk_info_create(1);

    connp = TSTransformCreate(ts_dechunk_transform_entry, txnp);
    TSContDataSet(connp, ctx);
    TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
    return 0;
}

static int
ts_chunked_transform_entry(TSCont contp, TSEvent event, void *edata)
{
    TSVIO       input_vio;

    ts_chunked_transform_ctx *transform_ctx = (ts_chunked_transform_ctx*)TSContDataGet(contp);

    if (TSVConnClosedGet(contp)) {
        TSContDestroy(contp);
        ts_chunked_destroy_transform_ctx(transform_ctx);
        return 0;
    }

    switch (event) {

        case TS_EVENT_ERROR:
            input_vio = TSVConnWriteVIOGet(contp);
            TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
            break;

        case TS_EVENT_VCONN_WRITE_COMPLETE:
            TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
            break;

        case TS_EVENT_VCONN_WRITE_READY:
        default:
            ts_chunked_transform_handler(contp, transform_ctx);
            break;
    }

    return 0;
}

static int
ts_dechunk_transform_entry(TSCont contp, TSEvent event, void *edata)
{
    TSVIO       input_vio;

    ts_dechunk_transform_ctx *transform_ctx = (ts_dechunk_transform_ctx*)TSContDataGet(contp);

    if (TSVConnClosedGet(contp)) {
        TSContDestroy(contp);
        ts_dechunk_destroy_transform_ctx(transform_ctx);
        return 0;
    }

    switch (event) {

        case TS_EVENT_ERROR:
            input_vio = TSVConnWriteVIOGet(contp);
            TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
            break;

        case TS_EVENT_VCONN_WRITE_COMPLETE:
            TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
            break;

        case TS_EVENT_VCONN_WRITE_READY:
        default:
            ts_dechunk_transform_handler(contp, transform_ctx);
            break;
    }

    return 0;
}

static int
ts_chunked_transform_handler(TSCont contp, ts_chunked_transform_ctx *tc)
{
    TSVConn             output_conn;
    TSVIO               input_vio;
    TSIOBufferReader    input_reader;
    int64_t             towrite, upstream_done, avail;
    int                 ret, eos;

    output_conn = TSTransformOutputVConnGet(contp);
    input_vio = TSVConnWriteVIOGet(contp);
    input_reader = TSVIOReaderGet(input_vio);

    if (!tc->output_buffer) {
        tc->output_buffer = TSIOBufferCreate();
        tc->output_reader = TSIOBufferReaderAlloc(tc->output_buffer);
        tc->output_vio = TSVConnWrite(output_conn, contp, tc->output_reader, INT64_MAX);
    }

    if (!TSVIOBufferGet(input_vio)) {
        TSVIONBytesSet(tc->output_vio, tc->total);
        TSVIOReenable(tc->output_vio);
        return 1;
    }

    towrite = TSVIONTodoGet(input_vio);
    upstream_done = TSVIONDoneGet(input_vio);

    avail = TSIOBufferReaderAvail(input_reader);

    if (towrite > avail) {
        towrite = avail;
        eos = 0;

    } else {
        eos = 1;
    }

    ret = ts_chunked_process(input_reader, tc->output_buffer, eos);

    if (ret < 0) {
        tc->total = TSVIONDoneGet(tc->output_vio) + TSIOBufferReaderAvail(tc->output_reader);
        TSVIONBytesSet(tc->output_vio, tc->total);
        TSVIOReenable(tc->output_vio);
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
        return ret;
    }

    if (!eos) {
        TSVIOReenable(tc->output_vio);
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_READY, input_vio);

    } else {
        tc->total = TSVIONDoneGet(tc->output_vio) + TSIOBufferReaderAvail(tc->output_reader);
        TSVIONBytesSet(tc->output_vio, tc->total);
        TSVIOReenable(tc->output_vio);
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_COMPLETE, input_vio);
    }

    return 1;
}

static int
ts_dechunk_transform_handler(TSCont contp, ts_dechunk_transform_ctx *tc)
{
    TSVConn             output_conn;
    TSVIO               input_vio;
    TSIOBufferReader    input_reader;
    int64_t             towrite, upstream_done, avail;
    int                 ret, eos;

    output_conn = TSTransformOutputVConnGet(contp);
    input_vio = TSVConnWriteVIOGet(contp);
    input_reader = TSVIOReaderGet(input_vio);

    if (!tc->output_buffer) {
        tc->output_buffer = TSIOBufferCreate();
        tc->output_reader = TSIOBufferReaderAlloc(tc->output_buffer);
        tc->output_vio = TSVConnWrite(output_conn, contp, tc->output_reader, INT64_MAX);
    }

    if (!TSVIOBufferGet(input_vio)) {
        TSVIONBytesSet(tc->output_vio, tc->total);
        TSVIOReenable(tc->output_vio);
        return 1;
    }

    towrite = TSVIONTodoGet(input_vio);
    upstream_done = TSVIONDoneGet(input_vio);

    avail = TSIOBufferReaderAvail(input_reader);

    if (towrite > avail) {
        towrite = avail;
        eos = 0;

    } else {
        eos = 1;
    }

    ret = ts_dechunk_process(tc->info, input_reader, tc->output_buffer, eos);

    if (ret < 0) {
        tc->total = TSVIONDoneGet(tc->output_vio) + TSIOBufferReaderAvail(tc->output_reader);
        TSVIONBytesSet(tc->output_vio, tc->total);
        TSVIOReenable(tc->output_vio);
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
        return ret;
    }

    if (!ret) {
        TSVIOReenable(tc->output_vio);
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_READY, input_vio);

    } else {

        tc->total = TSVIONDoneGet(tc->output_vio) + TSIOBufferReaderAvail(tc->output_reader);
        TSVIONBytesSet(tc->output_vio, tc->total);
        TSVIOReenable(tc->output_vio);
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_COMPLETE, input_vio);
    }

    return 1;
}

static void
ts_chunked_destroy_transform_ctx(ts_chunked_transform_ctx *transform_ctx)
{
    if (!transform_ctx)
        return;

    if (transform_ctx->output_reader)
        TSIOBufferReaderFree(transform_ctx->output_reader);

    if (transform_ctx->output_buffer)
        TSIOBufferDestroy(transform_ctx->output_buffer);

    TSfree(transform_ctx);
}

static void
ts_dechunk_destroy_transform_ctx(ts_dechunk_transform_ctx *transform_ctx)
{
    if (!transform_ctx)
        return;

    if (transform_ctx->output_reader)
        TSIOBufferReaderFree(transform_ctx->output_reader);

    if (transform_ctx->output_buffer)
        TSIOBufferDestroy(transform_ctx->output_buffer);

    ts_dechunk_info_destroy(transform_ctx->info);

    TSfree(transform_ctx);
}

