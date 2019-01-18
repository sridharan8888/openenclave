// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SOCKET_OPS_H
#define _OE_SOCKET_OPS_H

#include <openenclave/bits/types.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef uint32_t socklen_t;
struct oe_sockaddr;
struct oe_addrinfo;

typedef struct _oe_socket_ops
{
    int (*socket)(
        oe_device_t* dev,
        int domain,
        int type,
        int protocol);

    int (*connect)(
        oe_device_t* dev,
        int sockfd,
        const struct oe_sockaddr *addr,
        socklen_t addrlen);

    int (*accept)(
        oe_device_t* dev,
        int sockfd,
        struct oe_sockaddr *addr,
        socklen_t *addrlen);

    int (*bind)(
        oe_device_t* dev,
        int sockfd,
        const struct oe_sockaddr *addr,
        socklen_t addrlen);

    int (*listen)(
        oe_device_t* dev,
        int sockfd,
        int backlog);

    ssize_t (*recv)(
        oe_device_t* dev,
        int sockfd,
        void *buf,
        size_t len,
        int flags);

    ssize_t (*send)(
        oe_device_t* dev,
        int sockfd,
        const void *buf,
        size_t len,
        int flags);

    int (*shutdown)(
        oe_device_t* dev,
        int sockfd,
        int how);

    int (*getsockopt)(
        oe_device_t* dev,
        int sockfd,
        int level,
        int optname,
        void* optval,
        socklen_t* optlen);

    int (*setsockopt)(
        oe_device_t* dev,
        int sockfd,
        int level,
        int optname,
        const void* optval,
        socklen_t optlen);

    int (*getpeername)(
        oe_device_t* dev,
        int sockfd,
        struct oe_sockaddr *addr,
        socklen_t *addrlen);

    int (*getsockname)(
        oe_device_t* dev,
        int sockfd,
        struct oe_sockaddr *addr,
        socklen_t *addrlen);

    int (*getaddrinfo)(
        oe_device_t* dev,
        const char *node,
        const char *service,
        const struct oe_addrinfo *hints,
        struct oe_addrinfo **res);

    void (*freeaddrinfo)(
        oe_device_t* dev,
        struct oe_addrinfo *res);

    int (*gethostname)(
        oe_device_t* dev,
        char *name, size_t len);

    int (*getnameinfo)(
        oe_device_t* dev,
        const struct oe_sockaddr *sa,
        socklen_t salen,
        char *host,
        socklen_t hostlen,
        char *serv,
        socklen_t servlen,
        int flags);
}
oe_socket_ops_t;

/* ATTN: where does select go? */

OE_EXTERNC_END

#endif // _OE_SOCKET_OPS_H
