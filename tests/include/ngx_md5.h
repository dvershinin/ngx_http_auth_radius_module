#ifndef TEST_NGX_MD5_H
#define TEST_NGX_MD5_H

#include <openssl/md5.h>

typedef MD5_CTX ngx_md5_t;

#define ngx_md5_init(ctx) MD5_Init(ctx)
#define ngx_md5_update(ctx, data, len) MD5_Update((ctx), (data), (len))
#define ngx_md5_final(result, ctx) MD5_Final((result), (ctx))

#endif
