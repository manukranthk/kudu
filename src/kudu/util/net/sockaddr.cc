// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "kudu/util/net/sockaddr.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include "kudu/gutil/endian.h"
#include "kudu/gutil/macros.h"
#include "kudu/gutil/stringprintf.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/net/net_util.h"
#include "kudu/util/stopwatch.h"

namespace kudu {

using strings::Substitute;

///
/// Sockaddr
///
Sockaddr::Sockaddr() {
  memset(&addr6_, 0, sizeof(addr6_));
  addr6_.sin6_family = AF_INET6;
  addr6_.sin6_addr = IN6ADDR_ANY_INIT;
  memset(&addr_, 0, sizeof(addr_));
  addr_.sin_family = AF_INET;
  addr_.sin_addr.s_addr = INADDR_ANY;
}

Sockaddr::Sockaddr(const struct sockaddr_in& addr) {
  usingIpv6 = false;
  memcpy(&addr_, &addr, sizeof(struct sockaddr_in));
}

Sockaddr::Sockaddr(const struct sockaddr_in6& addr) {
  memcpy(&addr6_, &addr, sizeof(struct sockaddr_in6));
}

Status Sockaddr::ParseString(const std::string& s, uint16_t default_port) {
  HostPort hp;
  RETURN_NOT_OK(hp.ParseString(s, default_port));

  if (usingIpv6) {
    if (inet_pton(AF_INET6, hp.host().c_str(), &addr6_.sin6_addr.s6_addr) != 1) {
      return Status::InvalidArgument("Invalid IP address", hp.host());
    }
  } else {
    if (inet_pton(AF_INET, hp.host().c_str(), &addr_.sin_addr) != 1) {
      return Status::InvalidArgument("Invalid IP address", hp.host());
    }
  }
  set_port(hp.port());
  return Status::OK();
}

Sockaddr& Sockaddr::operator=(const struct sockaddr_in &addr) {
  usingIpv6 = false;
  memcpy(&addr_, &addr, sizeof(struct sockaddr_in));
  return *this;
}

Sockaddr& Sockaddr::operator=(const struct sockaddr_in6 &addr) {
  memcpy(&addr6_, &addr, sizeof(struct sockaddr_in6));
  return *this;
}

bool Sockaddr::operator==(const Sockaddr& other) const {
  if (usingIpv6) {
    return memcmp(&other.addr6_, &addr6_, sizeof(addr6_)) == 0;
  } else {
    return memcmp(&other.addr_, &addr_, sizeof(addr_)) == 0;
  }
}

bool Sockaddr::operator<(const Sockaddr &rhs) const {
  if (usingIpv6) {
    return memcmp(addr6_.sin6_addr.s6_addr,
        rhs.addr6_.sin6_addr.s6_addr, 16) < 0;
  } else {
    return addr_.sin_addr.s_addr < rhs.addr_.sin_addr.s_addr;
  }
}

uint32_t Sockaddr::HashCode() const {
  uint32_t ret = addr_.sin_addr.s_addr;
  ret ^= (addr_.sin_port * 7919);
  return ret;
}

void Sockaddr::set_port(int port) {
  if (usingIpv6) {
    addr6_.sin6_port = htons(port);
  } else {
    addr_.sin_port = htons(port);
  }
}

int Sockaddr::port() const {
  if (usingIpv6) {
    return ntohs(addr6_.sin6_port);
  } else {
    return ntohs(addr_.sin_port);
  }
}

std::string Sockaddr::host() const {
  if (!usingIpv6) {
    char str[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &addr_.sin_addr, str, INET_ADDRSTRLEN);
    return str;
  } else {
    char str[INET6_ADDRSTRLEN];
    ::inet_ntop(AF_INET6, addr6_.sin6_addr.s6_addr, str, INET6_ADDRSTRLEN);
    return str;
  }
}

const struct sockaddr_in& Sockaddr::addr() const {
  CHECK(!usingIpv6);
  return addr_;
}

const struct sockaddr_in6& Sockaddr::addr6() const {
  return addr6_;
}

std::string Sockaddr::ToString() const {
  if (usingIpv6) {
    char str[INET6_ADDRSTRLEN];
    ::inet_ntop(AF_INET6, &addr6_.sin6_addr.s6_addr, str, INET6_ADDRSTRLEN);
    return StringPrintf("%s:%d", str, port());
  } else {
    char str[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &addr_.sin_addr, str, INET_ADDRSTRLEN);
    return StringPrintf("%s:%d", str, port());
  }
}

std::string Sockaddr::ToStringCanonical() const {
  if (usingIpv6) {
    char str[INET6_ADDRSTRLEN];
    ::inet_ntop(AF_INET6, &addr6_.sin6_addr.s6_addr, str, INET6_ADDRSTRLEN);
    return StringPrintf("[%s]:%d", str, port());
  } else {
    char str[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &addr_.sin_addr, str, INET_ADDRSTRLEN);
    return StringPrintf("%s:%d", str, port());
  }
}

bool Sockaddr::IsWildcard() const {
  if (!usingIpv6) {
    return addr_.sin_addr.s_addr == 0;
  } else {
    uint32_t tmp = 0;
    for (auto c : addr6_.sin6_addr.s6_addr) {
      tmp |= c;
    }
    return tmp == 0;
  }
}

bool Sockaddr::IsAnyLocalAddress() const {
  if (usingIpv6) {
    struct sockaddr_in6 tmp;
    tmp.sin6_addr = IN6ADDR_LOOPBACK_INIT;
    return memcmp(&addr6_.sin6_addr.s6_addr, &tmp.sin6_addr.s6_addr,
        sizeof(addr6_.sin6_addr.s6_addr)) == 0;
  } else {
    return (NetworkByteOrder::FromHost32(addr_.sin_addr.s_addr) >> 24) == 127;
  }
}

Status Sockaddr::LookupHostname(string* hostname) const {
  char host[NI_MAXHOST];
  int flags = 0;

  int rc;
  LOG_SLOW_EXECUTION(WARNING, 200,
                     Substitute("DNS reverse-lookup for $0", ToString())) {
    if (usingIpv6) {
      rc = getnameinfo((struct sockaddr *) &addr6_, sizeof(sockaddr_in6),
                       host, NI_MAXHOST, nullptr, 0, flags);
    } else {
      rc = getnameinfo((struct sockaddr *) &addr_, sizeof(sockaddr_in),
                       host, NI_MAXHOST, nullptr, 0, flags);
    }
  }
  if (PREDICT_FALSE(rc != 0)) {
    if (rc == EAI_SYSTEM) {
      int errno_saved = errno;
      return Status::NetworkError(Substitute("getnameinfo: $0", gai_strerror(rc)),
                                  strerror(errno_saved), errno_saved);
    }
    return Status::NetworkError("getnameinfo", gai_strerror(rc), rc);
  }
  *hostname = host;
  return Status::OK();
}

} // namespace kudu
