#ifndef RADIUS_TEST_SUPPORT_H
#define RADIUS_TEST_SUPPORT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include <openssl/hmac.h>
#include <stdio.h>

#include "radius_lib.h"

#define RADIUS_HEADER_SIZE 20
#define MESSAGE_AUTHENTICATOR_TYPE 80
#define MESSAGE_AUTHENTICATOR_SIZE 18

#define STR(value) { sizeof(value) - 1, (u_char *) value }

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "%s:%d: check failed: %s\n",                     \
                    __FILE__, __LINE__, #condition);                           \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t golden_response[] = {
    0x02, 0x07, 0x00, 0x26, 0xf2, 0x7b, 0xca, 0x37,
    0xaf, 0x82, 0xdb, 0x2c, 0xd5, 0x5c, 0x37, 0x0f,
    0xff, 0xa6, 0x53, 0xdb, 0x50, 0x12, 0x84, 0xfd,
    0x9b, 0xf6, 0x87, 0xf8, 0xea, 0x1d, 0xa3, 0xa3,
    0x02, 0x0a, 0x4f, 0xe5, 0x5b, 0x04,
};

static const uint8_t request_authenticator[AUTH_BUF_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static uint8_t *
find_message_authenticator(uint8_t *packet, size_t len)
{
    size_t pos = RADIUS_HEADER_SIZE;

    while (pos + 2 <= len) {
        uint8_t attr_len = packet[pos + 1];
        if (attr_len < 2 || pos + attr_len > len) {
            return NULL;
        }
        if (packet[pos] == MESSAGE_AUTHENTICATOR_TYPE &&
            attr_len == MESSAGE_AUTHENTICATOR_SIZE) {
            return packet + pos + 2;
        }
        pos += attr_len;
    }

    return NULL;
}

static size_t
count_message_authenticators(const uint8_t *packet, size_t len)
{
    size_t count = 0;
    size_t pos = RADIUS_HEADER_SIZE;

    while (pos + 2 <= len) {
        uint8_t attr_len = packet[pos + 1];
        if (attr_len < 2 || pos + attr_len > len) {
            return count;
        }
        if (packet[pos] == MESSAGE_AUTHENTICATOR_TYPE) {
            count++;
        }
        pos += attr_len;
    }

    return count;
}

static void
independent_hmac(uint8_t digest[AUTH_BUF_SIZE],
                 const void *packet, size_t len,
                 const ngx_str_t *secret)
{
    unsigned int digest_len = 0;

    HMAC(EVP_md5(), secret->data, (int) secret->len,
         packet, len, digest, &digest_len);
    assert(digest_len == AUTH_BUF_SIZE);
}

static void
set_response_authenticator(uint8_t *packet, size_t len,
                           const uint8_t req_auth[AUTH_BUF_SIZE],
                           const ngx_str_t *secret)
{
    MD5_CTX md5;

    MD5_Init(&md5);
    MD5_Update(&md5, packet, 4);
    MD5_Update(&md5, req_auth, AUTH_BUF_SIZE);
    MD5_Update(&md5, packet + RADIUS_HEADER_SIZE,
               len - RADIUS_HEADER_SIZE);
    MD5_Update(&md5, secret->data, secret->len);
    MD5_Final(packet + 4, &md5);
}

static void
set_message_authenticator(uint8_t *packet, size_t len,
                          const uint8_t req_auth[AUTH_BUF_SIZE],
                          const ngx_str_t *secret)
{
    uint8_t digest[AUTH_BUF_SIZE];
    uint8_t *message_auth = find_message_authenticator(packet, len);

    assert(message_auth != NULL);
    memcpy(packet + 4, req_auth, AUTH_BUF_SIZE);
    memset(message_auth, 0, AUTH_BUF_SIZE);
    independent_hmac(digest, packet, len, secret);
    memcpy(message_auth, digest, AUTH_BUF_SIZE);
}

#endif
