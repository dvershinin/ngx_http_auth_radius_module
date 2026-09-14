#ifndef TEST_NGX_CORE_H
#define TEST_NGX_CORE_H

typedef unsigned char u_char;

typedef struct {
    size_t len;
    u_char *data;
} ngx_str_t;

#define ngx_memcpy(dst, src, len) memcpy((dst), (src), (len))
#define ngx_memcmp(left, right, len) memcmp((left), (right), (len))
#define ngx_memzero(buf, len) memset((buf), 0, (len))

#endif
