#!/usr/bin/env bash
# build.sh — Linux / macOS equivalent of build.bat for DecoderDetectorV2
# Usage: ./build.sh
# Edit BURP_JAR at top if needed.

set -o errexit
set -o nounset
set -o pipefail

# ----- CONFIGURE -----
# Set path to your Burp jar here (edit as necessary)
BURP_JAR="${BURP_JAR:-$HOME/.local/share/BurpSuitePro/burpsuite_pro.jar}"
# Java release to compile for (matches your Windows RELEASE var)
RELEASE="${RELEASE:-21}"

# ----- derived paths -----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src/main/java"
OUT_DIR="$SCRIPT_DIR/classes"
OUT_JAR="$SCRIPT_DIR/decoder-detector-v2.jar"
MANIFEST="$SCRIPT_DIR/manifest.txt"

# ----- helpers -----
err() { printf "[ERROR] %s\n" "$*" >&2; exit 1; }
info() { printf "[i] %s\n" "$*"; }

# ----- sanity checks -----
command -v javac >/dev/null 2>&1 || err "javac not found in PATH. Install JDK and ensure javac is on PATH."

if [[ ! -f "$BURP_JAR" ]]; then
  err "BURP jar not found at: $BURP_JAR
Update the BURP_JAR variable at top of build.sh or set env var BURP_JAR."
fi

if [[ ! -f "$MANIFEST" ]]; then
  err "manifest.txt not found at: $MANIFEST"
fi

# jar tool
JAR_CMD="$(command -v jar || true)"
if [[ -z "$JAR_CMD" ]]; then
  # On some systems `jar` isn't in PATH; try to find in JAVA_HOME
  if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/jar" ]]; then
    JAR_CMD="$JAVA_HOME/bin/jar"
  else
    err "jar (JDK tool) not found in PATH and JAVA_HOME not set or jar not present. Make sure JDK is installed."
  fi
fi

# ----- prepare output dir -----
if [[ -d "$OUT_DIR" ]]; then
  info "Removing existing $OUT_DIR ..."
  rm -rf -- "$OUT_DIR"
fi
mkdir -p -- "$OUT_DIR"

# ----- compile -----
info "Compiling Java sources from $SRC_DIR ..."
COMPILE_SUCCESS=0

# attempt with --release (preferred)
if javac -cp "$BURP_JAR" -d "$OUT_DIR" "$SRC_DIR"/*.java --release "$RELEASE"; then
  COMPILE_SUCCESS=1
else
  info "Compilation with --release $RELEASE failed — retrying without --release (using default source/target)..."
  # retry without --release
  if javac -cp "$BURP_JAR" -d "$OUT_DIR" "$SRC_DIR"/*.java; then
    COMPILE_SUCCESS=1
  else
    COMPILE_SUCCESS=0
  fi
fi

if [[ $COMPILE_SUCCESS -ne 1 ]]; then
  err "Compilation failed."
fi

# ----- create jar -----
if [[ -f "$OUT_JAR" ]]; then
  info "Removing existing $OUT_JAR ..."
  rm -f -- "$OUT_JAR"
fi

info "Creating jar $OUT_JAR using manifest $MANIFEST ..."
# -C "$OUT_DIR" . will add all classes from OUT_DIR root
if "$JAR_CMD" cfm "$OUT_JAR" "$MANIFEST" -C "$OUT_DIR" .; then
  info "[DONE] $OUT_JAR"
  printf "\nLoad in Burp: Extender -> Add -> Java -> select the jar\n"
else
  err "JAR creation failed."
fi

# optional pause-equivalent for interactive terminal
if [[ -t 0 ]]; then
  read -r -p "Press ENTER to exit..."
fi

exit 0
