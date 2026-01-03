# ReplicaPulse

ReplicaPulse is a lightweight MySQL change data capture (CDC) utility that streams replication/binlog events and emits deterministic SQL statements. It is written in modern C++20 with minimal dependencies.

## Features
- Connects as a replication client using the MySQL protocol and streams row-based events (MySQL 5.5/5.6/5.7/8.0/8.4 tested against protocol basics).
- Emits pure SQL for DDL and DML, including synthesized INSERT/UPDATE/DELETE statements from row events.
- Multi-threaded pipeline: IO reader, decoder, formatter workers, and writer with bounded queues to enforce backpressure.
- Schema cache driven by TABLE_MAP events with optional information_schema lookups for column names and primary keys.
- DDL statements flush cached table metadata so subsequent row events pull fresh schemas before SQL synthesis.
- Configurable output target (stdout or file) and worker parallelism.
- Automatic reconnect with exponential backoff and checkpointed binlog coordinates; malformed events are logged and skipped without aborting the stream.
- SQL output optionally annotated with GTID comments and binlog coordinates for replay/debugging (toggle with `--no-gtid` / `--no-binlog-coords`).
- Optional file-based HA lease so multiple nodes can contend for ownership and a standby can take over if the active node crashes.
- PREVIOUS_GTIDS_EVENT parsing captures the executed GTID set up front; per-transaction GTIDs extend the set for durable checkpoints, and sockets use configurable IO timeouts so Ctrl+C or HA failover exits promptly.
- GTID intervals are merged and deduplicated before checkpointing so failovers resume from compact, monotonic sets even after long runtimes.
- Understands binlog CRC32 checksums (MySQL 5.6+), stripping trailers and warning on mismatches so parsing keeps streaming instead of aborting.
- GTIDs are only persisted after COMMIT/autocommit boundaries to avoid skipping partially processed transactions during reconnects.
- Embeddable service API (`run_replicapulse`) for plugin/SDK use: supply a SQL callback sink to fold CDC into another application without spawning a separate process.
- Docker Compose demo spins up MySQL, runs a mixed DDL/DML workload, and captures ReplicaPulse output to prove end-to-end behavior.

## Quickstart
```bash
cmake -S . -B build
cmake --build build

# Run against a MySQL instance with binlog enabled
./build/replicapulse --host 127.0.0.1 --port 3306 --user repl --password secret \
    --server-id 1234 --start-binlog mysql-bin.000001 --start-pos 4 --output - \
    --checkpoint-file /var/lib/replicapulse.cp --ha-lease-file /var/lib/replicapulse.lease \
    --include-gtid --include-binlog-coords
```

### Embedding as a plugin/SDK
Link against the `replicapulse` library and supply a callback sink to receive SQL without spawning a child process:
```cpp
std::atomic<bool> stop{false};
replicapulse::ReplicaPulseConfig cfg;
cfg.host = "127.0.0.1";
cfg.user = "repl";
cfg.password = "secret";
cfg.start_position = replicapulse::StartPosition{"mysql-bin.000001", 4};

replicapulse::SqlSink sink;
sink.callback = [&](const std::string &sql) { /* forward to your queue/logger */ };
int rc = replicapulse::run_replicapulse(cfg, sink, stop);
```

### Command-line options
Run `replicapulse --help` to see the complete list of supported flags. Key options include:

- Connection: `--host`, `--port`, `--user`, `--password`, `--server-id`
- Start position: `--start-binlog` + `--start-pos`, or `--start-gtid` to begin from a GTID set
- Output: `--output -` (stdout) or a filepath, queue sizes (`--decode-queue-size`, `--work-queue-size`), and worker pool size (`--threads`)
- Checkpointing and HA: `--checkpoint-file`, `--ha-lease-file`, `--ha-node-id`, `--ha-timeout`
- Formatting toggles: `--include-gtid`/`--no-gtid` and `--include-binlog-coords`/`--no-binlog-coords`
- Networking: TLS (`--ssl`) plus IO/reconnect tuning (`--io-timeout-ms`, `--reconnect-delay-ms`, `--reconnect-delay-max-ms`)

### Docker Compose demo
A reproducible integration harness lives in `docker-compose.yml`. It boots MySQL with binlog enabled, runs a DDL/DML workload, and stores ReplicaPulse output in `docker/demo/output/output.sql`.
```bash
docker compose up --build --abort-on-container-exit
cat docker/demo/output/output.sql
# Validate the captured SQL contains the expected DDL/DML mix
bash docker/demo/verify_output.sh
```

## Tests
Unit tests are built with CTest. Run them via:
```bash
cmake -S . -B build -DENABLE_TESTING=ON
cmake --build build
ctest --test-dir build
```

To hunt memory leaks or undefined behavior during development, enable sanitizers:
```bash
cmake -S . -B build -DENABLE_TESTING=ON -DENABLE_SANITIZERS=ON
cmake --build build
ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build
```

## Production tuning
- The Docker image constrains glibc arenas (`MALLOC_ARENA_MAX=2`) to avoid heap bloat at high QPS; when deploying outside Docker,
  set the same environment variable or preload a tuned allocator (e.g., jemalloc/mimalloc) if desired.
- Size the decode/work queues (`--decode-queue-size`/`--work-queue-size`) and worker pool (`--threads`) to match binlog rate; backpressure propagates automatically to keep memory bounded.
- Keep checkpoints on fast storage and pin the HA lease file to a shared, low-latency path so failovers remain responsive.

## Limitations
- Most MySQL column types are decoded, but exotic types (e.g., GIS, custom collations) may still render as binary literals.
- The metadata query connection is optional; when unavailable, generic column names (colN) are used.
- ReplicaPulse keeps memory bounded with fixed-size queues and moves packets/rows between stages to avoid unbounded growth, but sustained throughput still depends on provisioning enough worker threads for the upstream workload.

