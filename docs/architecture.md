# ReplicaPulse Architecture

ReplicaPulse is organized as a streaming pipeline that turns MySQL binlog events into executable SQL text. The design favors low-latency processing, bounded memory usage, and clear separation of responsibilities.

## Threading Model
1. **IO Thread** – Maintains the replication connection to MySQL using the raw protocol. It reads binlog packets and pushes them into a bounded decode queue, pausing automatically when downstream stages apply backpressure. On errors the thread reconnects with exponential backoff, resuming from the last checkpointed binlog coordinate.
2. **Decode Thread** – Parses packets into typed `BinlogEvent` structures via `BinlogParser`, updates the table metadata cache from TABLE_MAP events, and forwards events to the work queue.
3. **Formatter Workers** – A pool of worker threads converts events into SQL strings using `SqlFormatter`. Ordering is preserved because each event produces a self-contained SQL fragment; the writer consumes results in FIFO order from the output queue.
4. **Writer Thread** – Streams SQL to stdout or a file. The bounded queue prevents unbounded buffering when the destination is slow.

## Metadata Cache
`TableMetadataCache` maps table IDs to schemas, column lists, and key information. TABLE_MAP events seed the cache with column types and nullable flags; an optional metadata connection issues `information_schema` queries to discover real column names and primary/unique keys. On DDL (seen via `QUERY_EVENT`), cache entries for the affected schema/table are invalidated so the next TABLE_MAP refreshes definitions before more row events are decoded.

## Event Parsing
`BinlogParser` understands common replication event types: FORMAT_DESCRIPTION, ROTATE, QUERY, TABLE_MAP, GTID, XID, and row events (WRITE/UPDATE/DELETE). Row events decode per-column values, preserving NULLs, binary payloads, and temporal types where possible. Uncommon column encodings fall back to length-coded byte strings, ensuring a lossless round-trip into SQL literals. Malformed or unsupported row events are wrapped as SQL comments instead of aborting the stream.

Events carry monotonically increasing sequence numbers assigned immediately after decode. Formatter workers preserve these sequence numbers; a single ordered writer buffers out-of-order completions and flushes SQL strictly in binlog order so multi-threaded formatting cannot reorder the stream.

## SQL Synthesis
`SqlFormatter` emits deterministic SQL:
- DDL and statement-based DML from `QUERY_EVENT` are forwarded verbatim.
- Row-based DML is synthesized as `INSERT`, `UPDATE`, or `DELETE`. Predicates prefer primary keys, then unique keys, falling back to all columns from the before-image.
- Values are escaped for SQL, with binary blobs emitted as hex literals and strings quoted safely.
- Transaction boundaries use `BEGIN`/`COMMIT` when GTID or XID events are present.
- Binlog coordinates and GTID comments can be included ahead of each statement for replay/debugging and toggled via CLI flags.

## Checkpointing, HA, and Reliability
ReplicaPulse persists the last safe binlog position and associated GTID set after every transaction commit or autocommit statement into a checkpoint file. GTIDs observed mid-transaction are not persisted until the `XID_EVENT`/implicit commit arrives to prevent skipping a partially emitted transaction on reconnect. On startup the checkpoint is automatically loaded unless an explicit `--start-binlog/--start-pos` override is provided. When IO errors occur the reader reconnects with exponential backoff and resumes from the checkpoint instead of exiting. Start positions support both binlog file/position and GTID sets so clusters mixing 5.5/5.6/5.7/8.0/8.4 can be tailed consistently.

For active/passive HA, an optional file-based lease (`--ha-lease-file`) allows multiple nodes to contend for ownership. The active node heartbeats the lease; if it crashes the standby will detect a stale lease and take over using the persisted checkpoint.

ReplicaPulse also consumes `PREVIOUS_GTIDS_EVENT` to seed the executed GTID set before the first transaction and appends each subsequent GTID as a merged interval. GTID ranges are deduplicated and compacted before being written to checkpoints so failovers resume with a minimal, monotonic set. Replication sockets are configured with short IO timeouts (tunable via `--io-timeout-ms`) so shutdown signals or lease loss stop the reader promptly instead of blocking forever on `recv`.

MySQL 5.6+ binlogs often include CRC32 checksums. The decoder detects checksum-enabled format description events, verifies the CRC (logging a warning on mismatches), strips the 4-byte trailer, and continues parsing so checksum differences do not halt the stream while still surfacing corruption.

## Embeddable API and plugin use
`run_replicapulse` exposes the full pipeline to embedders. Callers provide a `ReplicaPulseConfig` plus a `SqlSink` that can either stream to an `std::ostream` or a callback function. If both are provided, SQL is delivered to both destinations in binlog order. This allows hosting ReplicaPulse inside brokers or plugins without spawning a child process while retaining the same HA/ordering/metadata guarantees as the CLI.

## Load profile and memory safety
Bounded queues across IO/decode/format/output stages prevent unbounded buffering under heavy write load. Each queue now accepts move-only pushes to avoid extra allocations; worker threads reuse strings when building SQL to keep GC pressure low. The decoder keeps only the minimum metadata cache necessary for tables referenced by recent TABLE_MAP events; cache entries are evicted on DDL so stale rows do not accumulate. For high-QPS deployments, size the decode/work queues and worker pool to match network bandwidth—backpressure will propagate to the IO thread automatically without leaking memory.

The provided Docker image caps glibc arenas (`MALLOC_ARENA_MAX=2`) to reduce heap fragmentation, and developers can optionally build with `-DENABLE_SANITIZERS=ON` to chase leaks/UB before shipping. The `docker/demo/verify_output.sh` helper asserts the compose harness captured representative DDL/DML so CI runs can fail fast if streaming ever regresses.

## Docker Compose harness
`docker-compose.yml` builds the local source tree into a container, starts MySQL with GTID + row-based logging, runs an idempotent DDL/DML workload, and captures generated SQL into `docker/demo/output/output.sql`. The harness is self-contained and exercises DDL, INSERT/UPDATE/DELETE, TRUNCATE, and index DDL to verify ReplicaPulse output in a repeatable environment.
