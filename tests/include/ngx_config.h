#ifndef TEST_NGX_CONFIG_H
#define TEST_NGX_CONFIG_H

#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef htobe32
#define htobe32(value) htonl(value)
#endif

#ifndef htobe16
#define htobe16(value) htons(value)
#endif

#endif
