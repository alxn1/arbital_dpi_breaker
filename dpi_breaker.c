//
//  dpi_breaker.c
//  dpi_breaker
//
//  Created by alxn1 on 02/06/2019.
//  Copyright © 2019 alxn1. All rights reserved.
//

#include <stdbool.h>
#include <memory.h>
#include <unistd.h>
#include <sys/socket.h>

#define TLS_RAGMENT_COUNT_MAX 40

static bool is_http_request(const void *data, size_t size)
{
    typedef struct {
        const char *name;
        size_t      size;
    } method_t;

    static const method_t HTTP_METHODS[] = {
        { "GET ",     4 },
        { "HEAD ",    5 },
        { "POST ",    5 },
        { "PUT ",     4 },
        { "DELETE ",  7 },
        { "CONNECT ", 8 },
        { "OPTIONS ", 8 },
        { NULL,       0 }
    };

    for(const method_t *m = HTTP_METHODS; m->name != NULL; m++) {
        if(size >= m->size && memcmp(m->name, data, m->size) == 0)
            return true;
    }

    return false;
}

static bool is_tls_version(uint16_t version)
{
    static const uint16_t TLS_VERSIONS[] = {
        0x0300,
        0x0301,
        0x0302,
        0x0303,
        0x0
    };

    for(const uint16_t *v = TLS_VERSIONS; *v != 0; v++) {
        if(version == *v)
            return true;
    }

    return false;
}

static bool is_tls_client_hello(const void *data, size_t size)
{
/*
example:

16          Content Type: Handshake (22)
03 03       Version: TLS 1.2 (0x0303)
00 dc       Length: 220
            Handshake Protocol: Client Hello
01              Handshake Type: Client Hello (1)
00 00 d8        Length: 216
03 03           Version: TLS 1.2 (0x0303)
*/

    static const size_t  TLS_MIN_PACKET_SIZE            = 11;
    static const uint8_t TLS_CONTENT_TYPE_HANDSHAKE     = 22;
    static const uint8_t TLS_MESSAGE_TYPE_CLIENT_HELLO  = 1;

    if(size >= TLS_MIN_PACKET_SIZE) {
        const uint8_t *ptr = data;

        uint8_t  content_type;
        uint8_t  message_type;
        uint16_t version_a;
        uint16_t version_b;

        memcpy(&content_type, ptr + 0, sizeof(content_type));
        memcpy(&message_type, ptr + 5, sizeof(message_type));
        memcpy(&version_a,    ptr + 1, sizeof(version_a));
        memcpy(&version_b,    ptr + 9, sizeof(version_b));

        return (content_type == TLS_CONTENT_TYPE_HANDSHAKE &&
                message_type == TLS_MESSAGE_TYPE_CLIENT_HELLO &&
                is_tls_version(htons(version_a)) &&
                is_tls_version(htons(version_b)));
    }

    return false;
}

static ssize_t dpi_breaker_write(int fd, const void *data, size_t size)
{
    if(is_tls_client_hello(data, size)) {
        size_t fragment_count = size > TLS_RAGMENT_COUNT_MAX?
            TLS_RAGMENT_COUNT_MAX: size;

        for(size_t i = 0; i < fragment_count; ++i) {
            if(write(fd, data + i, 1) == -1)
                return -1;
        }

        return fragment_count;
    }

    if(is_http_request(data, size) && write(fd, "\n", 1) == -1)
        return -1;

    return write(fd, data, size);
}

static ssize_t dpi_breaker_send(int fd, const void *data, size_t size, int flags)
{
    if(is_tls_client_hello(data, size)) {
        size_t fragment_count = size > TLS_RAGMENT_COUNT_MAX?
            TLS_RAGMENT_COUNT_MAX: size;

        for(size_t i = 0; i < fragment_count; ++i) {
            if(send(fd, data + i, 1, flags) == -1)
                return -1;
        }

        return fragment_count;
    }

    if (is_http_request(data, size) && send(fd, "\n", 1, flags) == -1)
        return -1;

    return send(fd, data, size, flags);
}

#define DYLD_INTERPOSE(_replacment, _replacee) \
    __attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
        __attribute__((section("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

DYLD_INTERPOSE(dpi_breaker_write, write) // for Chrome (not tested), Opera and etc
DYLD_INTERPOSE(dpi_breaker_send,  send)  // Firefox use send
