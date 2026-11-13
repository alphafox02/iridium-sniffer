/*
 * Network utility helpers
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __NET_UTIL_H__
#define __NET_UTIL_H__

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Resolve a hostname or numeric IP to an IPv4 address.
 * Tries inet_pton first (numeric), falls back to getaddrinfo (DNS).
 * Returns 0 on success, -1 on failure.
 */
static inline int resolve_host_ipv4(const char *host, struct in_addr *out)
{
    if (inet_pton(AF_INET, host, out) == 1)
        return 0;

    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
        return -1;

    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

/*
 * TCP connect with a timeout; a plain connect() to a host that doesn't
 * answer blocks for about two minutes. Returns a blocking fd or -1.
 */
static inline int tcp_connect_timeout(const struct sockaddr *addr,
                                      socklen_t addrlen, int timeout_ms)
{
    int fd = socket(addr->sa_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, addr, addrlen);
    if (rc < 0 && errno == EINPROGRESS) {
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        int err = 0;
        socklen_t len = sizeof(err);
        if (poll(&p, 1, timeout_ms) == 1 &&
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0)
            rc = 0;
    }
    if (rc < 0) {
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, flags);
    return fd;
}

#endif
