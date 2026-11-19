#!/usr/bin/env bash
#
# mayhem/build.sh — build xv6's fuzz targets and functional tests natively on x86-64.
#
# xv6 is a RISC-V teaching kernel normally run under QEMU. Its portable C (the file-system kernel
# and the user programs) compiles unmodified for the host, so instead of booting QEMU we compile
# those upstream files with the fuzz flags, link them into partial objects, and prefix every xv6
# symbol (xv6k_ for the kernel, xv6_ for user code) so they cannot clash with libc. The xv6
# objects' writable data is moved into named sections so a harness can snapshot all kernel/user
# globals once and restore them before each input. The glue (locks, the one process, RAM disk,
# user syscalls) is in mayhem/harness/.
#
# Outputs (all under mayhem/bin/, gitignored):
#   fuzz_fs_syscalls, fuzz_fs_image, fuzz_exec, fuzz_kernel_printk, fuzz_user_printf, fuzz_grep (+ -standalone)  libFuzzer
#   sh_afl                                                                       AFL, file input
#   fs_selftest, user_selftest, sh_test, fs.img                                  for mayhem/test.sh
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
H="$SRC/mayhem/harness"
B="$SRC/mayhem/build"
OUT="$SRC/mayhem/bin"
mkdir -p "$B" "$OUT"

KERNEL_SRCS="kernel/fs.c kernel/log.c kernel/bio.c kernel/file.c kernel/sysfile.c kernel/pipe.c kernel/sleeplock.c kernel/string.c kernel/console.c kernel/exec.c $H/kstubs.c"
USER_LIB="user/printf.c user/ulib.c user/umalloc.c $H/ustubs.c"
# xv6 is freestanding code with its own memset/strlen/printf...; it is compiled as such.
XV6_CFLAGS="-ffreestanding -fno-builtin -fno-common -fno-stack-protector -w -I$SRC"

# mkxv6 <out.o> <symbol prefix> <section prefix> <cc> <cflags> <sources...>
# Compile, `ld -r` into one object, prefix every symbol except the h_* host interface and the
# compiler runtimes, and rename the writable data sections to <section prefix>_data/_bss.
mkxv6() {
  local out="$1" pfx="$2" sec="$3" cc="$4" cflags="$5"; shift 5
  local d="$out.d"
  rm -rf "$d"; mkdir -p "$d"
  local objs=() i=0
  for s in "$@"; do
    i=$((i + 1))
    # shellcheck disable=SC2086
    "$cc" $cflags $XV6_CFLAGS -c "$s" -o "$d/$i.o"
    objs+=("$d/$i.o")
  done
  ld -r -o "$d/all.o" "${objs[@]}"
  nm "$d/all.o" | awk '{print $NF}' | sort -u \
    | grep -Ev '^(h_|__asan|__ubsan|__sanitizer|__sancov|__lsan|__start_|__stop_|__afl|__llvm|__cmplog|_GLOBAL_OFFSET_TABLE_|\.|asan\.|sancov\.)' \
    | grep -E '^[A-Za-z_][A-Za-z0-9_]*$' | awk -v p="$pfx" '{print $1, p $1}' > "$d/syms.txt"
  # ASan gives each instrumented global its own .bss.<name>/.data.<name> section: rename them all.
  local ren=() s2
  for s2 in $(objdump -h "$d/all.o" | awk '$1 ~ /^[0-9]+$/ {print $2}' \
      | grep -E '^\.(bss|data)(\..*)?$' | grep -v '^\.data\.rel\.ro' | sort -u); do
    case "$s2" in
      .bss*) ren+=(--rename-section "$s2=${sec}_bss") ;;
      *) ren+=(--rename-section "$s2=${sec}_data") ;;
    esac
  done
  objcopy --redefine-syms="$d/syms.txt" "${ren[@]}" "$d/all.o" "$out"
}

# --- the file-system image every kernel harness mounts (upstream's mkfs, as the Makefile does) ---
"$CC" -O1 -Wall -I"$SRC" -o "$B/mkfs" mkfs/mkfs.c
rm -f "$B/fs.img"
(cd "$B" && cp "$SRC/README" README && ./mkfs fs.img README >/dev/null && rm -f README \
  && ld -r -b binary -o fsimg.o fs.img)
cp "$B/fs.img" "$OUT/fs.img"

# --- fuzz builds: project + harness with sanitizers, coverage and DWARF 3 ---
FZ="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
mkxv6 "$B/kfs_fuzz.o" xv6k_ xv6k "$CC" "$FZ" $KERNEL_SRCS
mkxv6 "$B/kprintk_fuzz.o" xv6k_ xv6p "$CC" "$FZ" kernel/printk.c kernel/string.c $H/pstubs.c
mkxv6 "$B/uprintf_fuzz.o" xv6_ xv6u "$CC" "$FZ" $USER_LIB
mkxv6 "$B/ugrep_fuzz.o" xv6_ xv6u "$CC" "$FZ" user/grep.c $USER_LIB
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$H/lsan_off.c" -o "$B/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

link_target() { # <name> <harness.c> <objs...>
  local name="$1" src="$2"; shift 2
  "$CC" $FZ -I"$H" -c "$src" -o "$B/$name.o"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$name.o" "$@" "$B/lsan_off.o" -o "$OUT/$name"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/$name.o" "$@" "$B/lsan_off.o" -o "$OUT/$name-standalone"
}
"$CC" $FZ -I"$H" -c "$H/kfs_host.c" -o "$B/kfs_host_fuzz.o"
"$CC" $FZ -I"$H" -c "$H/uhost.c" -o "$B/uhost_fuzz.o"
link_target fuzz_fs_syscalls "$H/fuzz_fs_syscalls.c" "$B/kfs_fuzz.o" "$B/kfs_host_fuzz.o" "$B/fsimg.o"
link_target fuzz_fs_image "$H/fuzz_fs_image.c" "$B/kfs_fuzz.o" "$B/kfs_host_fuzz.o" "$B/fsimg.o"
link_target fuzz_exec "$H/fuzz_exec.c" "$B/kfs_fuzz.o" "$B/kfs_host_fuzz.o" "$B/fsimg.o"
link_target fuzz_kernel_printk "$H/fuzz_kernel_printk.c" "$B/kprintk_fuzz.o"
link_target fuzz_user_printf "$H/fuzz_user_printf.c" "$B/uprintf_fuzz.o" "$B/uhost_fuzz.o"
link_target fuzz_grep "$H/fuzz_grep.c" "$B/ugrep_fuzz.o" "$B/uhost_fuzz.o"

# sh: a file-input AFL target (sh's error path is exit()).
AFLF="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
mkxv6 "$B/ush_afl.o" xv6_ xv6u afl-clang-fast "$AFLF" user/sh.c $USER_LIB
afl-clang-fast $AFLF -I"$H" -c "$H/uhost.c" -o "$B/uhost_afl.o"
afl-clang-fast $AFLF -I"$H" -c "$H/sh_main.c" -o "$B/sh_main_afl.o"
afl-clang-fast $AFLF "$B/sh_main_afl.o" "$B/ush_afl.o" "$B/uhost_afl.o" "$B/lsan_off.o" -o "$OUT/sh_afl"

# --- functional tests: same upstream code, normal flags (no sanitizers/fuzzer) ---
TF="-O1 -g $COVERAGE_FLAGS"
mkxv6 "$B/kfs_test.o" xv6k_ xv6k "$CC" "$TF" $KERNEL_SRCS
mkxv6 "$B/kprintk_test.o" xv6k_ xv6p "$CC" "$TF" kernel/printk.c kernel/string.c $H/pstubs.c
mkxv6 "$B/ugrep_test.o" xv6_ xv6u "$CC" "$TF" user/grep.c $USER_LIB
mkxv6 "$B/ush_test.o" xv6_ xv6u "$CC" "$TF" user/sh.c $USER_LIB
"$CC" $TF -I"$H" "$H/fs_selftest.c" "$H/kfs_host.c" "$B/kfs_test.o" "$B/fsimg.o" -o "$OUT/fs_selftest"
"$CC" $TF -I"$H" "$H/printk_selftest.c" "$B/kprintk_test.o" -o "$OUT/printk_selftest"
"$CC" $TF -I"$H" "$H/user_selftest.c" "$H/uhost.c" "$B/ugrep_test.o" -o "$OUT/user_selftest"
"$CC" $TF -I"$H" "$H/sh_main.c" "$H/uhost.c" "$B/ush_test.o" -o "$OUT/sh_test"

echo "built: $(ls "$OUT" | tr '\n' ' ')"
