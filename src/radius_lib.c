#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include <assert.h>
#include "radius_lib.h"

typedef struct {
    uint8_t         d[AUTH_BUF_SIZE];
} radius_auth_t;

typedef struct {
    uint8_t         code;
    uint8_t         id;
    uint16_t        len;
    radius_auth_t   auth;
} radius_hdr_t;

typedef struct {
    uint8_t         type;
    uint8_t         len;
} radius_attr_hdr_t;

typedef struct {
    radius_hdr_t    hdr;
    uint8_t         attrs[RADIUS_PKG_MAX - sizeof(radius_hdr_t)];
} radius_pkg_t;

typedef struct {
    radius_pkg_t   *pkg;
    uint8_t        *pos;
} radius_pkg_builder_t;

// Data Type Definitions
// https://www.rfc-editor.org/rfc/rfc8044#section-3
typedef enum {
    radius_attr_type_integer,
    radius_attr_type_string,
} radius_attr_type_t;

typedef enum {
    radius_err_ok,
    radius_err_range,
    radius_err_mem,
} radius_error_t;

typedef struct {
    radius_attr_type_t type;
    uint8_t            len_min;
    uint8_t            len_max;
} radius_attr_desc_t;

// Packet Types
// https://www.rfc-editor.org/rfc/rfc2865#section-4
#define RADIUS_CODE_ACCESS_REQUEST      1
#define RADIUS_CODE_ACCESS_ACCEPT       2
#define RADIUS_CODE_ACCESS_REJECT       3

// Attributes
// https://www.rfc-editor.org/rfc/rfc2865#section-5
#define RADIUS_ATTR_USER_NAME           1
#define RADIUS_ATTR_USER_PASSWORD       2
#define RADIUS_ATTR_SERVICE_TYPE        6
#define RADIUS_ATTR_NAS_IDENTIFIER      32
#define RADIUS_ATTR_MESSAGE_AUTHENTICATOR 80

#define RADIUS_AUTHENTICATE_ONLY        8
#define RADIUS_HMAC_MD5_BLOCK_SIZE      64

#define RADIUS_ATTR_DESC_ITEM(t, lmin, lmax) \
    .type = t,                               \
    .len_min = lmin,                         \
    .len_max = lmax

static radius_attr_desc_t attrs_desc[] = {
    [RADIUS_ATTR_USER_NAME] = {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_string, 1, 63)
    },
    [RADIUS_ATTR_USER_PASSWORD] = {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_string, 16, 128)
    },
    [RADIUS_ATTR_SERVICE_TYPE] = {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_integer,
                              sizeof(uint32_t), sizeof(uint32_t))
    },
    [RADIUS_ATTR_NAS_IDENTIFIER] = {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_string, 3, 64)
    },
};

static void
init_radius_pkg(radius_pkg_builder_t *b, void *buf, int len);

static void
gen_auth(radius_auth_t *auth);

static radius_error_t
check_attr_len_needed(radius_pkg_builder_t *b,
                      uint16_t len);

static radius_error_t
check_string_attr_len_range(radius_pkg_builder_t *b,
                            int radius_attr_id,
                            uint16_t len);

static radius_error_t
make_access_request_pkg(radius_pkg_builder_t *b,
                        uint8_t req_id,
                        const ngx_str_t *secret,
                        const ngx_str_t *user,
                        const ngx_str_t *passwd,
                        const ngx_str_t *nas_id);

static radius_error_t
update_pkg_len(radius_pkg_builder_t *b);

typedef struct {
    ngx_md5_t       inner;
    ngx_md5_t       outer;
} radius_hmac_md5_t;

static void
hmac_md5_init(radius_hmac_md5_t *ctx,
              const ngx_str_t *key);

static void
hmac_md5_update(radius_hmac_md5_t *ctx,
                const void *data,
                size_t len);

static void
hmac_md5_final(uint8_t digest[AUTH_BUF_SIZE],
               radius_hmac_md5_t *ctx);

static int
auth_equal(const uint8_t *actual,
           const uint8_t *expected);

static radius_error_t
put_message_authenticator(radius_pkg_builder_t *b,
                          uint8_t **value);

static int
find_message_authenticator(const radius_pkg_t *pkg,
                           size_t len,
                           const uint8_t **value);

static void
calc_response_authenticator(uint8_t digest[AUTH_BUF_SIZE],
                            const radius_pkg_t *pkg,
                            size_t len,
                            const uint8_t *req_auth,
                            const ngx_str_t *secret);

static void
calc_message_authenticator(uint8_t digest[AUTH_BUF_SIZE],
                           const radius_pkg_t *pkg,
                           size_t len,
                           const uint8_t *req_auth,
                           const uint8_t *message_auth,
                           const ngx_str_t *secret);

size_t
create_radius_pkg(void *buf, size_t len,
                  uint8_t req_id,
                  const ngx_str_t *user,
                  const ngx_str_t *passwd,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id,
                  uint8_t /*out*/ *req_auth)
{
    radius_pkg_builder_t b;
    radius_error_t rc;
    uint8_t *message_auth;

    init_radius_pkg(&b, buf, len);
    gen_auth(&b.pkg->hdr.auth);
    rc = make_access_request_pkg(&b, req_id, secret, user, passwd, nas_id);
    if (rc != radius_err_ok) {
        return 0;
    }

    rc = put_message_authenticator(&b, &message_auth);
    if (rc != radius_err_ok) {
        return 0;
    }

    rc = update_pkg_len(&b);
    if (rc != radius_err_ok) {
        return 0;
    }

    radius_hmac_md5_t hmac;
    hmac_md5_init(&hmac, secret);
    hmac_md5_update(&hmac, b.pkg, b.pos - (uint8_t *) b.pkg);
    hmac_md5_final(message_auth, &hmac);

    if (req_auth) {
        ngx_memcpy(req_auth, &b.pkg->hdr.auth, sizeof(b.pkg->hdr.auth));
    }

    return b.pos - (uint8_t *)b.pkg;
}

int
parse_radius_pkg(const void *buf, size_t len,
                 uint8_t req_id,
                 const uint8_t *req_auth,
                 const ngx_str_t *secret)
{
    const radius_pkg_t *pkg = buf;
    const uint8_t *message_auth;
    uint8_t expected_auth[AUTH_BUF_SIZE];

    if (len < sizeof(radius_hdr_t)) {
        return RADIUS_PARSE_ERR_LENGTH;
    }

    uint16_t pkg_len = ntohs(pkg->hdr.len);
    if (pkg_len < sizeof(radius_hdr_t) ||
        pkg_len > RADIUS_PKG_MAX ||
        pkg_len != len) {
        return RADIUS_PARSE_ERR_LENGTH;
    }

    // Check correlation id matches
    if (req_id != pkg->hdr.id) {
        return RADIUS_PARSE_ERR_ID;
    }

    if (find_message_authenticator(pkg, pkg_len, &message_auth) != 0) {
        return RADIUS_PARSE_ERR_ATTRIBUTE;
    }

    calc_response_authenticator(expected_auth, pkg, pkg_len,
                                req_auth, secret);
    if (!auth_equal(pkg->hdr.auth.d, expected_auth)) {
        return RADIUS_PARSE_ERR_RESPONSE_AUTH;
    }

    if (message_auth != NULL) {
        calc_message_authenticator(expected_auth, pkg, pkg_len,
                                   req_auth, message_auth, secret);
        if (!auth_equal(message_auth, expected_auth)) {
            return RADIUS_PARSE_ERR_MESSAGE_AUTH;
        }
    }

    if (pkg->hdr.code == RADIUS_CODE_ACCESS_ACCEPT) {
        return RADIUS_AUTH_ACCEPTED;
    } else {
        return RADIUS_AUTH_REJECTED;
    }
}

static void
init_radius_pkg(radius_pkg_builder_t *b, void *buf, int len)
{
    b->pkg = buf;
    assert(len == RADIUS_PKG_MAX);
    b->pos = b->pkg->attrs;
}

static void
gen_auth(radius_auth_t *auth)
{
    uint8_t i;
    for (i = 0; i < sizeof(radius_auth_t); i++) {
        auth->d[i] = (uint8_t)(random() & UCHAR_MAX);
    }
}

static void
hmac_md5_init(radius_hmac_md5_t *ctx,
              const ngx_str_t *key)
{
    uint8_t key_block[RADIUS_HMAC_MD5_BLOCK_SIZE];
    uint8_t inner_pad[RADIUS_HMAC_MD5_BLOCK_SIZE];
    uint8_t outer_pad[RADIUS_HMAC_MD5_BLOCK_SIZE];
    uint8_t hashed_key[AUTH_BUF_SIZE];
    size_t i;

    ngx_memzero(key_block, sizeof(key_block));
    if (key->len > sizeof(key_block)) {
        ngx_md5_t md5;
        ngx_md5_init(&md5);
        ngx_md5_update(&md5, key->data, key->len);
        ngx_md5_final(hashed_key, &md5);
        ngx_memcpy(key_block, hashed_key, sizeof(hashed_key));
        ngx_memzero(hashed_key, sizeof(hashed_key));
    } else if (key->len > 0) {
        ngx_memcpy(key_block, key->data, key->len);
    }

    for (i = 0; i < sizeof(key_block); ++i) {
        inner_pad[i] = key_block[i] ^ 0x36;
        outer_pad[i] = key_block[i] ^ 0x5c;
    }

    ngx_md5_init(&ctx->inner);
    ngx_md5_update(&ctx->inner, inner_pad, sizeof(inner_pad));
    ngx_md5_init(&ctx->outer);
    ngx_md5_update(&ctx->outer, outer_pad, sizeof(outer_pad));

    ngx_memzero(key_block, sizeof(key_block));
    ngx_memzero(inner_pad, sizeof(inner_pad));
    ngx_memzero(outer_pad, sizeof(outer_pad));
}

static void
hmac_md5_update(radius_hmac_md5_t *ctx,
                const void *data,
                size_t len)
{
    ngx_md5_update(&ctx->inner, data, len);
}

static void
hmac_md5_final(uint8_t digest[AUTH_BUF_SIZE],
               radius_hmac_md5_t *ctx)
{
    uint8_t inner_digest[AUTH_BUF_SIZE];

    ngx_md5_final(inner_digest, &ctx->inner);
    ngx_md5_update(&ctx->outer, inner_digest, sizeof(inner_digest));
    ngx_md5_final(digest, &ctx->outer);
    ngx_memzero(inner_digest, sizeof(inner_digest));
}

static int
auth_equal(const uint8_t *actual,
           const uint8_t *expected)
{
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < AUTH_BUF_SIZE; ++i) {
        diff |= actual[i] ^ expected[i];
    }

    return diff == 0;
}

static radius_error_t
check_attr_len_needed(radius_pkg_builder_t *b,
                      uint16_t len)
{
    size_t remain = sizeof(b->pkg->attrs) - (b->pos - b->pkg->attrs);
    size_t attr_len_need = sizeof(radius_attr_hdr_t) + len;
    if (attr_len_need > remain) {
        return radius_err_mem;
    }

    return radius_err_ok;
}

static radius_error_t
check_string_attr_len_range(radius_pkg_builder_t *b,
                            int radius_attr_id,
                            uint16_t len)
{
    if (len < attrs_desc[radius_attr_id].len_min ||
        len > attrs_desc[radius_attr_id].len_max) {
        return radius_err_range;
    }

    return check_attr_len_needed(b, len);
}

static radius_error_t
put_message_authenticator(radius_pkg_builder_t *b,
                          uint8_t **value)
{
    radius_error_t rc = check_attr_len_needed(b, AUTH_BUF_SIZE);
    if (rc != radius_err_ok) {
        return rc;
    }

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *) b->pos;
    ah->type = RADIUS_ATTR_MESSAGE_AUTHENTICATOR;
    ah->len = sizeof(radius_attr_hdr_t) + AUTH_BUF_SIZE;
    b->pos += sizeof(radius_attr_hdr_t);

    *value = b->pos;
    ngx_memzero(*value, AUTH_BUF_SIZE);
    b->pos += AUTH_BUF_SIZE;

    return radius_err_ok;
}

static int
find_message_authenticator(const radius_pkg_t *pkg,
                           size_t len,
                           const uint8_t **value)
{
    const uint8_t *pos = pkg->attrs;
    const uint8_t *end = (const uint8_t *) pkg + len;

    *value = NULL;
    while (pos < end) {
        size_t remaining = end - pos;
        if (remaining < sizeof(radius_attr_hdr_t)) {
            return -1;
        }

        const radius_attr_hdr_t *ah = (const radius_attr_hdr_t *) pos;
        if (ah->len < sizeof(radius_attr_hdr_t) || ah->len > remaining) {
            return -1;
        }

        if (ah->type == RADIUS_ATTR_MESSAGE_AUTHENTICATOR) {
            if (ah->len != sizeof(radius_attr_hdr_t) + AUTH_BUF_SIZE ||
                *value != NULL) {
                return -1;
            }
            *value = pos + sizeof(radius_attr_hdr_t);
        }

        pos += ah->len;
    }

    return 0;
}

static void
calc_response_authenticator(uint8_t digest[AUTH_BUF_SIZE],
                            const radius_pkg_t *pkg,
                            size_t len,
                            const uint8_t *req_auth,
                            const ngx_str_t *secret)
{
    ngx_md5_t ctx;
    size_t prefix_len = offsetof(radius_hdr_t, auth);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, pkg, prefix_len);
    ngx_md5_update(&ctx, req_auth, AUTH_BUF_SIZE);
    ngx_md5_update(&ctx, pkg->attrs, len - sizeof(radius_hdr_t));
    ngx_md5_update(&ctx, secret->data, secret->len);
    ngx_md5_final(digest, &ctx);
}

static void
calc_message_authenticator(uint8_t digest[AUTH_BUF_SIZE],
                           const radius_pkg_t *pkg,
                           size_t len,
                           const uint8_t *req_auth,
                           const uint8_t *message_auth,
                           const ngx_str_t *secret)
{
    static const uint8_t zeros[AUTH_BUF_SIZE];
    const uint8_t *packet = (const uint8_t *) pkg;
    const uint8_t *after_message_auth = message_auth + AUTH_BUF_SIZE;
    const uint8_t *end = packet + len;
    size_t prefix_len = offsetof(radius_hdr_t, auth);
    radius_hmac_md5_t hmac;

    hmac_md5_init(&hmac, secret);
    hmac_md5_update(&hmac, packet, prefix_len);
    hmac_md5_update(&hmac, req_auth, AUTH_BUF_SIZE);
    hmac_md5_update(&hmac, pkg->attrs,
                    message_auth - (const uint8_t *) pkg->attrs);
    hmac_md5_update(&hmac, zeros, sizeof(zeros));
    hmac_md5_update(&hmac, after_message_auth,
                    end - after_message_auth);
    hmac_md5_final(digest, &hmac);
}

static radius_error_t
put_passwd_crypt(radius_pkg_builder_t *b,
                 const ngx_str_t *secret,
                 const ngx_str_t *passwd)
{
    if (passwd->len > attrs_desc[RADIUS_ATTR_USER_PASSWORD].len_max) {
        return radius_err_range;
    }

    uint16_t pwd_padded_len = 16 * (1 + passwd->len / 16);
    radius_error_t rc = check_string_attr_len_range(b,
                                                    RADIUS_ATTR_USER_PASSWORD,
                                                    pwd_padded_len);
    if (rc != radius_err_ok) {
        return rc;
    }

    ngx_md5_t ctx;
    ngx_md5_t s_ctx;

    ngx_md5_init(&s_ctx);
    ngx_md5_update(&s_ctx, secret->data, secret->len);

    ctx = s_ctx;
    ngx_md5_update(&ctx, &b->pkg->hdr.auth, sizeof(b->pkg->hdr.auth));

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *) b->pos;

    ah->type = RADIUS_ATTR_USER_PASSWORD;
    b->pos += sizeof(radius_attr_hdr_t);

    ngx_md5_final(b->pos, &ctx);

    uint16_t pwd_remain = passwd->len;
    uint16_t pwd_padded_remain = pwd_padded_len;
    uint8_t *p = passwd->data;
    uint8_t *c = b->pos;

    ah->len = sizeof(radius_attr_hdr_t) + pwd_padded_remain;

    uint8_t i;
    while (pwd_padded_remain) {
        for(i = 0; i < 16; i++) {
            *c++ ^= pwd_remain ? *p++ : 0;
            if (pwd_remain) {
                pwd_remain--;
            }
        }
        ctx = s_ctx;
        pwd_padded_remain -= 16;
        if (!pwd_padded_remain) {
            b->pos += 16;
            break;
        }
        ngx_md5_update(&ctx, b->pos, c - b->pos);
        b->pos += 16;
        ngx_md5_final(b->pos, &ctx);
    }

    return radius_err_ok;
}

static int
put_string_attr(radius_pkg_builder_t *b,
                int radius_attr_id,
                const ngx_str_t *str)
{
    radius_error_t rc = check_string_attr_len_range(b,
                                                    radius_attr_id,
                                                    str->len);
    if (rc != radius_err_ok) {
        return rc;
    }

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *) b->pos;
    ah->type = radius_attr_id;
    ah->len = sizeof(radius_attr_hdr_t) + str->len;
    b->pos += sizeof(radius_attr_hdr_t);
    ngx_memcpy(b->pos, str->data, str->len);
    b->pos += str->len;

    return radius_err_ok;
}

static radius_error_t
put_integer_attr(radius_pkg_builder_t* b,
                 int radius_attr_id,
                 uint32_t value)
{
    radius_error_t rc = check_attr_len_needed(b, sizeof(value));
    if (rc != radius_err_ok) {
        return rc;
    }

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *) b->pos;
    ah->type = radius_attr_id;
    ah->len = sizeof(radius_attr_hdr_t) + sizeof(value);
    b->pos += sizeof(radius_attr_hdr_t);
    uint32_t encoded = htonl(value);
    ngx_memcpy(b->pos, &encoded, sizeof(encoded));
    b->pos += sizeof(value);

    return radius_err_ok;
}

static radius_error_t
make_access_request_pkg(radius_pkg_builder_t *b,
                        uint8_t req_id,
                        const ngx_str_t *secret,
                        const ngx_str_t *user,
                        const ngx_str_t *passwd,
                        const ngx_str_t *nas_id)
{
    assert(b && user && passwd);
    b->pkg->hdr.code = RADIUS_CODE_ACCESS_REQUEST;
    b->pkg->hdr.id = req_id;

    radius_error_t rc;
    // User-Name
    // https://www.rfc-editor.org/rfc/rfc2865#section-5.1
    if (user->len > 0) {
        rc = put_string_attr(b, RADIUS_ATTR_USER_NAME, user);
        if (rc != radius_err_ok) {
            return rc;
        }
    }

    // User-Password
    // https://www.rfc-editor.org/rfc/rfc2865#section-5.2
    if (passwd->len > 0) {
        rc = put_passwd_crypt(b, secret, passwd);
        if (rc != radius_err_ok) {
            return rc;
        }
    }

    // Service-Type
    // https://www.rfc-editor.org/rfc/rfc2865#section-5.6
    rc = put_integer_attr(b, RADIUS_ATTR_SERVICE_TYPE,
                          RADIUS_AUTHENTICATE_ONLY);
    if (rc != radius_err_ok) {
        return rc;
    }

    // NAS-Identifier
    // https://www.rfc-editor.org/rfc/rfc2865#section-5.32
    if (nas_id->len >= 3) {
        rc = put_string_attr(b, RADIUS_ATTR_NAS_IDENTIFIER, nas_id);
        if (rc != radius_err_ok) {
            return rc;
        }
    }

    return radius_err_ok;
}

static radius_error_t
update_pkg_len(radius_pkg_builder_t *b)
{
    uint16_t len = b->pos - (uint8_t *) &b->pkg->hdr;
    b->pkg->hdr.len = htons(len);
    return radius_err_ok;
}
