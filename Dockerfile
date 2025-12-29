FROM debian:12 AS build
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential cmake libssl-dev ca-certificates default-mysql-client && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
RUN cmake -S . -B /build -DENABLE_TESTING=OFF \
 && cmake --build /build --target replicapulse_cli --config Release

FROM debian:12-slim
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libssl3 ca-certificates default-mysql-client && \
    rm -rf /var/lib/apt/lists/*
ENV MALLOC_ARENA_MAX=2
COPY --from=build /build/replicapulse /usr/local/bin/replicapulse
COPY docker/demo/replicapulse_entrypoint.sh /usr/local/bin/replicapulse_entrypoint.sh
RUN chmod +x /usr/local/bin/replicapulse_entrypoint.sh
ENTRYPOINT ["/usr/local/bin/replicapulse_entrypoint.sh"]
CMD ["--help"]
