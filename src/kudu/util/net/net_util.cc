// Copyright (c) 2013, Cloudera, inc.

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <algorithm>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <tr1/unordered_set>
#include <utility>
#include <vector>

#include "kudu/gutil/gscoped_ptr.h"
#include "kudu/gutil/map-util.h"
#include "kudu/gutil/strings/numbers.h"
#include "kudu/gutil/strings/split.h"
#include "kudu/gutil/strings/strip.h"
#include "kudu/gutil/strings/util.h"
#include "kudu/util/errno.h"
#include "kudu/util/net/net_util.h"
#include "kudu/util/net/sockaddr.h"

using std::tr1::unordered_set;
using std::vector;

namespace kudu {

namespace {
struct AddrinfoDeleter {
  void operator()(struct addrinfo* info) {
    freeaddrinfo(info);
  }
};
}

HostPort::HostPort()
  : host_(""),
    port_(0) {
}

HostPort::HostPort(const std::string& host, uint16_t port)
  : host_(host),
    port_(port) {
}

HostPort::HostPort(const Sockaddr& addr)
  : host_(addr.host()),
    port_(addr.port()) {
}

Status HostPort::ParseString(const string& str, uint16_t default_port) {
  std::pair<string, string> p = strings::Split(str, strings::delimiter::Limit(":", 1));

  // Strip any whitespace from the host.
  StripWhiteSpace(&p.first);

  // Parse the port.
  uint32_t port;
  if (p.second.empty() && strcount(str, ':') == 0) {
    // No port specified.
    port = default_port;
  } else if (!SimpleAtoi(p.second, &port) ||
             port > 65535) {
    return Status::InvalidArgument("Invalid port", str);
  }

  host_.swap(p.first);
  port_ = port;
  return Status::OK();
}

Status HostPort::ResolveAddresses(vector<Sockaddr>* addresses) const {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* res = NULL;
  int rc = getaddrinfo(host_.c_str(), NULL, &hints, &res);
  if (rc != 0) {
    return Status::NetworkError(
      StringPrintf("Unable to resolve address '%s'", host_.c_str()),
      gai_strerror(rc));
  }
  gscoped_ptr<addrinfo, AddrinfoDeleter> scoped_res(res);
  for (; res != NULL; res = res->ai_next) {
    CHECK_EQ(res->ai_family, AF_INET);
    struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    addr->sin_port = htons(port_);
    Sockaddr sockaddr(*addr);
    if (addresses) {
      addresses->push_back(sockaddr);
    }
    VLOG(1) << "Resolved address " << sockaddr.ToString()
            << " for host/port " << ToString();
  }
  return Status::OK();
}

string HostPort::ToString() const {
  return host_ + ":" + boost::lexical_cast<string>(port_);
}

bool IsPrivilegedPort(uint16_t port) {
  return port <= 1024 && port != 0;
}

Status ParseAddressList(const std::string& addr_list,
                        uint16_t default_port,
                        std::vector<Sockaddr>* addresses) {
  vector<string> addr_strings = strings::Split(addr_list, ",", strings::SkipEmpty());

  unordered_set<Sockaddr> uniqued;

  BOOST_FOREACH(const string& addr_string, addr_strings) {
    vector<Sockaddr> this_addresses;
    HostPort host_port;
    RETURN_NOT_OK(host_port.ParseString(addr_string, default_port));
    RETURN_NOT_OK(host_port.ResolveAddresses(&this_addresses));
    // Only add the unique ones -- the user may have specified
    // some IP addresses in multiple ways
    BOOST_FOREACH(const Sockaddr& addr, this_addresses) {
      if (!InsertIfNotPresent(&uniqued, addr)) {
        LOG(INFO) << "Address " << addr.ToString() << " for " << host_port.ToString()
                  << " duplicates an earlier resolved entry.";
      }
    }
  }

  std::copy(uniqued.begin(), uniqued.end(), std::back_inserter(*addresses));
  return Status::OK();
}

Status GetHostname(string* hostname) {
  char name[HOST_NAME_MAX];
  int ret = gethostname(name, HOST_NAME_MAX);
  if (ret != 0) {
    return Status::NetworkError("Unable to determine local hostname",
                                ErrnoToString(errno),
                                errno);
  }
  *hostname = name;
  return Status::OK();
}

} // namespace kudu