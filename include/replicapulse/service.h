#pragma once

#include "config.h"
#include "output.h"

#include <atomic>

namespace replicapulse {

// Run ReplicaPulse until stop_flag is set or a fatal error occurs.
// Returns 0 on graceful exit, non-zero on configuration/connection failures.
int run_replicapulse(const ReplicaPulseConfig &config, const SqlSink &sink, std::atomic<bool> &stop_flag);

}

