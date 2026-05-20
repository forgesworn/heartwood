#!/bin/sh
# Heartwood container entrypoint.
#
# Modes:
#   serve         (default) run heartwood-device, bunker sidecar, and Tor together
#   heartwood     run only the heartwood-device binary
#   bunker        run only the bunker sidecar
#   test          run cargo-test artefacts already in the image, plus bunker tests
#   --version     print version info and exit
#   sh            drop into a shell
set -eu

MODE="${1:-serve}"

case "$MODE" in
  --version|version)
    # Static info only — the heartwood binary has no --version flag; it would
    # try to start as a server, which is not what we want for a smoke test.
    echo "arch:       $(uname -m)"
    echo "kernel:     $(uname -srm)"
    if [ -x /usr/local/bin/heartwood ]; then
      SIZE=$(wc -c < /usr/local/bin/heartwood 2>/dev/null | tr -d ' ')
      echo "heartwood:  /usr/local/bin/heartwood (${SIZE} bytes, executable)"
    else
      echo "heartwood:  missing or not executable"
      exit 1
    fi
    echo "node:       $(node --version)"
    echo "tor:        $(tor --version 2>/dev/null | head -1 || echo unknown)"
    exit 0
    ;;

  test)
    # Cross-arch verification path. With docker buildx + qemu this runs
    # inside the emulated TARGETARCH container, which proves the binary
    # and bunker code execute correctly on that architecture.
    echo "--- arch ---"
    uname -srm
    echo
    echo "--- heartwood binary ---"
    if [ -x /usr/local/bin/heartwood ]; then
      SIZE=$(wc -c < /usr/local/bin/heartwood 2>/dev/null | tr -d ' ')
      echo "/usr/local/bin/heartwood (${SIZE} bytes, executable)"
    else
      echo "heartwood binary missing or not executable" >&2
      exit 1
    fi
    echo
    echo "--- bunker node --test suite ---"
    cd "$HEARTWOOD_BUNKER_DIR"
    # Node 20 doesn't auto-expand globs in --test; enumerate explicitly.
    TESTS=$(find test -name "*.test.mjs" -type f | sort)
    if [ -z "$TESTS" ]; then
      echo "no test files found under $HEARTWOOD_BUNKER_DIR/test" >&2
      exit 1
    fi
    echo "running:"
    echo "$TESTS" | sed 's/^/  /'
    echo
    # shellcheck disable=SC2086
    exec node --test $TESTS
    ;;

  heartwood)
    shift || true
    exec heartwood "$@"
    ;;

  bunker)
    shift || true
    cd "$HEARTWOOD_BUNKER_DIR"
    exec node index.mjs "$@"
    ;;

  sh|shell)
    exec /bin/sh
    ;;

  serve)
    # Cooperative shutdown: tini (PID 1) forwards signals; each backgrounded
    # process is killed on TERM so we don't leak when the container stops.
    PIDS=""
    trap 'echo "shutting down..."; for p in $PIDS; do kill -TERM "$p" 2>/dev/null || true; done; wait' TERM INT

    # Tor (writes hidden service into /var/lib/tor/heartwood by default).
    if [ -r /etc/tor/torrc.heartwood ]; then
      tor -f /etc/tor/torrc.heartwood &
      PIDS="$PIDS $!"
      echo "started tor (pid $!)"
    fi

    # Bunker sidecar.
    (cd "$HEARTWOOD_BUNKER_DIR" && node index.mjs) &
    PIDS="$PIDS $!"
    echo "started bunker (pid $!)"

    # heartwood-device — kept in foreground so logs stream out and exits propagate.
    echo "starting heartwood-device on $HEARTWOOD_BIND"
    heartwood &
    DEVICE_PID=$!
    PIDS="$PIDS $DEVICE_PID"
    wait "$DEVICE_PID"
    EXIT_CODE=$?
    # If heartwood-device dies, take everything else down too.
    for p in $PIDS; do kill -TERM "$p" 2>/dev/null || true; done
    wait
    exit "$EXIT_CODE"
    ;;

  *)
    # Fall through: run whatever was passed as a normal command.
    exec "$@"
    ;;
esac
