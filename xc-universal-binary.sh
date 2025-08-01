#!/usr/bin/env bash
set -eEuvx

function error_help()
{
    ERROR_MSG="It looks like something went wrong building the Example App Universal Binary."
    echo "error: ${ERROR_MSG}"
}
trap error_help ERR

# XCode tries to be helpful and overwrites the PATH. Reset that.
PATH="$(bash -l -c 'echo $PATH')"

# This should be invoked from inside xcode, not manually
if [[ "${#}" -ne 4 ]]
then
    echo "Usage (note: only call inside xcode!):"
    echo "path/to/build-scripts/xc-universal-binary.sh <FFI_TARGET> <SRC_ROOT_PATH> <buildvariant>"
    exit 1
fi
#manifest target
CARGO_TARGET=${1}

# what to pass to cargo build -p, e.g. logins_ffi
FFI_TARGET=${2}
# path to source code root
SRC_ROOT=${3}
# buildvariant from our xcconfigs
BUILDVARIANT=$(echo "${4}" | tr '[:upper:]' '[:lower:]')

RELFLAG=
if [[ "${BUILDVARIANT}" != "debug" ]]; then
    RELFLAG=--release
fi

if [[ -n "${SDK_DIR:-}" ]]; then
  # Assume we're in Xcode, which means we're probably cross-compiling.
  # In this case, we need to add an extra library search path for build scripts and proc-macros,
  # which run on the host instead of the target.
  # (macOS Big Sur does not have linkable libraries in /usr/lib/.)
  export LIBRARY_PATH="${SDK_DIR}/usr/lib:${LIBRARY_PATH:-}"
fi

IS_SIMULATOR=0
if [ "${LLVM_TARGET_TRIPLE_SUFFIX-}" = "-simulator" ]; then
  IS_SIMULATOR=1
fi

#ARCHS=(x86_64 arm64)
echo "Building for ${ARCHS}"
for arch in $ARCHS; do
  case "$arch" in
    x86_64)
      if [ $IS_SIMULATOR -eq 0 ]; then
        echo "Building for x86_64, but not a simulator build. What's going on?" >&2
        exit 2
      fi

      # Intel iOS simulator
      export CFLAGS_x86_64_apple_ios="-target x86_64-apple-ios"
      $HOME/.cargo/bin/cargo rustc --manifest-path "${CARGO_TARGET}" -p "${FFI_TARGET}" --lib --crate-type staticlib $RELFLAG --target x86_64-apple-ios
      ;;

    arm64)
      if [ $IS_SIMULATOR -eq 0 ]; then
        # Hardware iOS targets
        $HOME/.cargo/bin/cargo rustc --manifest-path "${CARGO_TARGET}" -p "${FFI_TARGET}" --lib --crate-type staticlib $RELFLAG --target aarch64-apple-ios
      else
        # M1 iOS simulator
        $HOME/.cargo/bin/cargo rustc --manifest-path "${CARGO_TARGET}" -p "${FFI_TARGET}" --lib --crate-type staticlib $RELFLAG --target aarch64-apple-ios-sim
      fi
  esac
done
