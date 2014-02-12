// Copyright (c) 2013, Cloudera, inc.
#ifndef KUDU_INTEGRATION_TESTS_EXTERNAL_MINI_CLUSTER_H
#define KUDU_INTEGRATION_TESTS_EXTERNAL_MINI_CLUSTER_H

#include <string>
#include <vector>

#include "gutil/gscoped_ptr.h"
#include "gutil/macros.h"
#include "gutil/ref_counted.h"
#include "util/status.h"

namespace kudu {

class ExternalDaemon;
class ExternalMaster;
class ExternalTabletServer;
class HostPort;
class Subprocess;

namespace server {
class ServerStatusPB;
} // namespace server

struct ExternalMiniClusterOptions {
  ExternalMiniClusterOptions();
  ~ExternalMiniClusterOptions();

  // Number of TS to start.
  // Default: 1
  int num_tablet_servers;

  // Directory in which to store data.
  // Default: "", which auto-generates a unique path for this cluster.
  std::string data_root;

  // The path where the kudu daemons should be run from.
  // Default: "", which uses the same path as the currently running executable.
  // This works for unit tests, since they all end up in build/latest/.
  std::string daemon_bin_path;
};

// A mini-cluster made up of subprocesses running each of the daemons
// separately. This is useful for black-box or grey-box failure testing
// purposes -- it provides the ability to forcibly kill or stop particular
// cluster participants, which isn't feasible in the normal MiniCluster.
// On the other hand, there is little access to inspect the internal state
// of the daemons.
class ExternalMiniCluster {
 public:
  explicit ExternalMiniCluster(const ExternalMiniClusterOptions& opts);
  ~ExternalMiniCluster();

  // Start the cluster.
  Status Start();

  // Like the previous method but performs initialization synchronously, i.e.
  // this will wait for all TS's to be started and initialized. Tests should
  // use this if they interact with tablets immediately after Start();
  Status StartSync();

  // Add a new TS to the cluster. The new TS is started.
  // Requires that the master is already running.
  Status AddTabletServer();

  // Shuts down the cluster.
  // Currently, this uses SIGKILL on each daemon for a non-graceful shutdown.
  void Shutdown();

  // Return a pointer to the running master. This may be NULL if the cluster
  // is not started.
  ExternalMaster* master() { return master_.get(); }

  ExternalTabletServer* tablet_server(int idx) {
    CHECK_LT(idx, tablet_servers_.size());
    return tablet_servers_[idx].get();
  }

 private:
  Status StartMaster();

  std::string GetBinaryPath(const std::string& binary) const;
  std::string GetDataPath(const std::string& daemon_id) const;

  Status DeduceBinRoot(std::string* ret);
  Status HandleOptions();

  const ExternalMiniClusterOptions opts_;

  // The root for binaries.
  std::string daemon_bin_path_;

  std::string data_root_;

  bool started_;

  scoped_refptr<ExternalMaster> master_;
  std::vector<scoped_refptr<ExternalTabletServer> > tablet_servers_;

  DISALLOW_COPY_AND_ASSIGN(ExternalMiniCluster);
};

class ExternalDaemon : public base::RefCountedThreadSafe<ExternalDaemon> {
 public:
  ExternalDaemon(const std::string& exe, const std::string& data_dir);

  HostPort bound_rpc_hostport() const;
  HostPort bound_http_hostport() const;

  virtual void Shutdown();

 protected:
  friend class base::RefCountedThreadSafe<ExternalDaemon>;
  virtual ~ExternalDaemon();
  Status StartProcess(const std::vector<std::string>& flags);

  const std::string exe_;
  const std::string data_dir_;

  gscoped_ptr<Subprocess> process_;

  gscoped_ptr<server::ServerStatusPB> status_;

  DISALLOW_COPY_AND_ASSIGN(ExternalDaemon);
};


class ExternalMaster : public ExternalDaemon {
 public:
  ExternalMaster(const std::string& exe, const std::string& data_dir);

  Status Start();

 private:
  friend class base::RefCountedThreadSafe<ExternalMaster>;
  virtual ~ExternalMaster();
};

class ExternalTabletServer : public ExternalDaemon {
 public:
  ExternalTabletServer(const std::string& exe, const std::string& data_dir,
                       const HostPort& master_addr);

  Status Start();

 private:
  const std::string master_addr_;

  friend class base::RefCountedThreadSafe<ExternalTabletServer>;
  virtual ~ExternalTabletServer();
};

} // namespace kudu
#endif /* KUDU_INTEGRATION_TESTS_EXTERNAL_MINI_CLUSTER_H */
