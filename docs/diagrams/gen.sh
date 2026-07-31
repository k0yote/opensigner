#!/usr/bin/env sh

set -e

# install-d2.sh installs to ~/.local/bin by default, which build hosts
# (Vercel included) do not put on PATH.
PATH="$HOME/.local/bin:$PATH"

OUTPUT_DIR="public/diagrams"
DIAGRAMS_DIR="diagrams"

mkdir -p "$OUTPUT_DIR"

# A bare `wait` always returns 0, so collect each compile's status explicitly:
# a failed diagram must fail the build, not ship a stale or missing SVG.
pids=""
for file in "$DIAGRAMS_DIR"/*.d2; do
    [ -f "$file" ] || continue

    base_name="$(basename "$file" .d2)"
    output_file="$OUTPUT_DIR/${base_name}.svg"

    d2 --pad=0 --theme 101 --dark-theme 200 "$file" "$output_file" &
    pids="$pids $!"
done

failed=0
for pid in $pids; do
    wait "$pid" || failed=1
done
exit "$failed"
