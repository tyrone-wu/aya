#!/usr/bin/env bash

set -euo pipefail

# This script has been manually tested and verified on Ubuntu 24.04 with these kernel versions on
# the latest patch revision from https://cdn.kernel.org/pub/linux/kernel.
TESTED_KERNS=(
  3.19.8
  4.1.52
  4.7.10
  4.8.17
  4.9.337
  4.10.17
  4.13.16
  4.14.336
  4.15.18
  4.17.19
  4.18.20
  4.19.325
  4.20.17
  5.2.21
  5.3.18
  5.5.19
  5.6.19
  5.7.19
  5.9.16
  5.14.21
  6.4.16
)

# Check for required argument.
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <kernel-version>"
  exit 1
fi

KERN="$1"
if [[ ! "${TESTED_KERNS[*]}" =~ "$KERN" ]]; then
  echo "Kernel version $KERN has not been tested. Check this script for versions that have been tested."
  exit 1
fi

MAJOR=$(echo "$KERN" | cut -d. -f1)
MINOR=$(echo "$KERN" | cut -d. -f2)
PATCH=$(echo "$KERN" | cut -d. -f3)

# Install build dependencies.
sudo apt update -y
sudo apt install -y build-essential bc bison flex libssl-dev libelf-dev libncurses-dev dwarves # binutils-dev

# Download and unpack kernel source.
wget https://cdn.kernel.org/pub/linux/kernel/v"${MAJOR}".x/linux-"${KERN}".tar.xz
tar -xf linux-"${KERN}".tar.xz

# Setting `HOSTCFLAGS` does not work since it is overridden in the Makefile.
HOSTCC_FLAGS=""
CC_FLAGS=""
KCFLAGS_EXTRA=""

# Newer GCC versions have stricter static-analysis checks which may flag issues in older
# kernels. Since the build is configured to flag all warnings as errors, it will stop
# compilation. Because these are just warnings and not outright build failures, it is okay to
# proceed with compilation.
#
# We opt to stay on the default GCC and suppress or patch these warnings (see logic below).
cd linux-"${KERN}"
case "$MAJOR.$MINOR.$PATCH" in
  3.19.8)
    # Newer GCC versions give the error:
    # `include/linux/compiler-gcc.h: fatal error: linux/compiler-gcc13.h: No such file or directory`.
    #
    # A hacky workaround is to copy and rename `include/linux/compiler-gcc*.h` to
    # `include/linux/compiler-gcc13.h` [0]. Not sure why this works, but should be okay since it
    # builds successfully.
    #
    # [0] https://askubuntu.com/questions/1157084/fatal-error-linux-compiler-gcc7-h-no-such-file-or-directory
    cp include/linux/compiler-gcc5.h include/linux/compiler-gcc13.h
    ;;&
  3.19.8 | 4.7.10)
    # GCC 6+ `-pie` flag causes the error: `code model kernel does not support PIC mode`. There
    # isn't a direct patch file, so we extract it from:
    # https://lists.ubuntu.com/archives/kernel-team/2016-May/077178.html
    curl -sL https://lists.ubuntu.com/archives/kernel-team/2016-May/077178.html \
      | awk "/^diff --git/{flag=1} flag{print} /^-- $/{exit}" \
      > disable_pie.patch
    patch -F3 -p1 < disable_pie.patch
    ;;&
  4.13.16)
    # Newer binutils version causes the error: `Unsupported relocation type: R_X86_64_PLT32`.
    # Patch: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b21ebf2fb4cde1618915a97cc773e287ff49173e
    wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=b21ebf2fb4cde1618915a97cc773e287ff49173e \
      -O R_X86_64_PLT32.patch
    patch -F3 -p1 < R_X86_64_PLT32.patch
    ;;&
  4.15.18)
    # Newer GNU Make versions changed how `#` character is parsed, resulting in the error:
    # `.fixdep.o.cmd:1: *** missing separator.`
    # Patch: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9feeb638cde083c737e295c0547f1b4f28e99583
    # Patch: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9564a8cf422d7b58f6e857e3546d346fa970191e
    wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=9feeb638cde083c737e295c0547f1b4f28e99583 \
      -O tools_missing_separator.patch
    wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=9564a8cf422d7b58f6e857e3546d346fa970191e \
      -O kbuild_missing_separator.patch
    patch -p1 < tools_missing_separator.patch
    patch -p1 < kbuild_missing_separator.patch

    # GCC 10+ `-fno-common` flag causes the error in `pgtable_64.c` & `pagetable.c`: `multiple
    # definition of '__force_order'` [0]. There is no patch for the `pagetable.c` file
    # specifically, so we instead pass the `-fcommon` flag.
    #
    # [0] https://lkml.iu.edu/2003.1/03102.html
    CC_FLAGS+=" -fcommon"

    # GCC 13 flags `‘restrict’-qualified parameter` warning, which should be safe to safe to ignore.
    HOSTCC_FLAGS+=" -Wno-error=restrict"
    # GCC 13 flags `deprecated-declarations` warning for `elf_getshnum` & `elf_getshstrndx`, which
    # should be safe to safe to ignore.
    HOSTCC_FLAGS+=" -Wno-error=deprecated-declarations"
    ;;&
  4.13.16 | 4.15.18 | 4.17.19 | 4.18.20 | 4.20.17)
    # Newer host kernel versions causes the error: `#error New address family defined, please update secclass_map.`.
    # Patch: https://lore.kernel.org/selinux/20190225005528.28371-1-paulo@paulo.ac
    wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=ff1bf4c0714e7936330bb316090a75eaa35061e7 \
      -O pf_max.patch
    patch -F3 -p1 < pf_max.patch
    ;;&
  4.18.20 | 4.20.17 | 5.2.21)
    # GCC 10+ `-fcf-protection=branch` flag conflicts with `-mindirect-branch` [0], which gives the
    # error: `'-mindirect-branch' and '-fcf-protection' are not compatible`.
    #
    # [0] https://lore.kernel.org/lkml/20210208162543.GH17908@zn.tnic
    KCFLAGS_EXTRA+=" -fcf-protection=none"
    ;;&
  4.17.19 | 4.18.20 | 4.20.17 | 5.2.21 | 5.3.18)
    # GCC 10+ `-fno-common` flag causes the error in `pgtable_64.c` & `kaslr_64.c`: `multiple
    # definition of '__force_order'`.
    # Patch: https://lore.kernel.org/lkml/20200124181811.4780-1-hjl.tools@gmail.com
    wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=df6d4f9db79c1a5d6f48b59db35ccd1e9ff9adfc \
      -O kaslr_64__force_order.patch
    patch -p1 < kaslr_64__force_order.patch
    ;;&
  4.15.18 | 4.17.19 | 4.18.20 | 4.20.17 | 5.2.21 | 5.3.18)
    # GCC 13 flags `redundant-decls` warning, which should be safe to ignore.
    HOSTCC_FLAGS+=" -Wno-error=redundant-decls"
    ;;&
  4.15.18 | 4.17.19 | 4.18.20 | 4.20.17 | 5.2.21 | 5.3.18 | 5.5.19 | 5.6.19 | 5.7.19 | 5.9.16)
    # Newer binutils version causes the error: `arch/x86/entry/thunk_64.o: warning: objtool: missing symbol table`.
    # Patch: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1d489151e9f9d1647110277ff77282fe4d96d09b
    wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=1d489151e9f9d1647110277ff77282fe4d96d09b \
      -O objtool_symtable.patch
    patch -p1 < objtool_symtable.patch
    ;;&
  4.15.18 | 4.17.19 | 4.18.20 | 4.20.17 | 5.2.21 | 5.3.18 | 5.5.19 | 5.6.19 | 5.7.19 | 5.9.16 | 5.14.21)
    # GCC 13 flags `use-after-free` warning, which should be safe to ignore.
    HOSTCC_FLAGS+=" -Wno-error=use-after-free"
    ;;
  # These version compiles with GCC 13 without any additional flags or patches.
  4.1.52 | 4.8.17 | 4.9.337 | 4.10.17 | 4.14.336 | 4.19.325 | 6.4.16)
    ;;
  *)
    ;;
esac

# Using default config omits some BPF features we need. To ensure full support, the we base the
# `.config` off of our Debain image's `.config`.
wget https://mirrors.wikimedia.org/debian/pool/main/l/linux/linux-image-6.12.27-cloud-amd64-unsigned_6.12.27-1_amd64.deb \
  -O debian-image-6.12.27.deb
dpkg --fsys-tarfile debian-image-6.12.27.deb | tar -xO ./boot/config-6.12.27-cloud-amd64 > .config
# Build new config file using the existing `.config`.
make olddefconfig

# Build the compressed kernel image.
make -j"$(nproc)" \
  ${HOSTCC_FLAGS:+HOSTCC="gcc $HOSTCC_FLAGS"} \
  ${CC_FLAGS:+CC="gcc $CC_FLAGS"} \
  ${KCFLAGS_EXTRA:+KCFLAGS="$KCFLAGS_EXTRA"} \
  bzImage

mkdir ../vmlinuz-"${KERN}"
cp arch/x86/boot/bzImage ../vmlinuz-"${KERN}"/vmlinuz
cp .config ../vmlinuz-"${KERN}"/config

# ignore bottom
# older GCC versions that i might not end up using

# HOSTCC_FLAGS=""
# case "$MAJOR.$MINOR" in
#   # GCC 11 tested on: 4.19, 5.4, 5.5.19, 5.6.19, 5.7.19, 5.9.16
#   4.19 | 5.[0-9])
#     sudo apt install -y gcc-11 g++-11
#     HOSTCC_FLAGS="HOSTCC=gcc-11 CC=gcc-11"
#     ;;
#   # GCC 12 tested on: 5.14.21
#   5.14.21)
#     sudo apt install -y gcc-12 g++-12
#     HOSTCC_FLAGS="HOSTCC=gcc-12 CC=gcc-12"
#     ;;
#   # GCC 13 (default on ubuntu 24.04): 6.4
#   *)
#     ;;
# esac

# # gcc-4.8 & g++-4.8 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.8/gcc-4.8-base_4.8.5-4ubuntu8_amd64.deb
# # gcc-4.8 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.8/cpp-4.8_4.8.5-4ubuntu8_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.8/libgcc-4.8-dev_4.8.5-4ubuntu8_amd64.deb
# # g++-4.8 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.8/libstdc++-4.8-dev_4.8.5-4ubuntu8_amd64.deb
# # libgcc-4.8-dev dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.8/libasan0_4.8.5-4ubuntu8_amd64.deb

# sudo apt install -y \
#   ./libasan0_4.8.5-4ubuntu8_amd64.deb \
#   ./libstdc++-4.8-dev_4.8.5-4ubuntu8_amd64.deb \
#   ./libgcc-4.8-dev_4.8.5-4ubuntu8_amd64.deb \
#   ./cpp-4.8_4.8.5-4ubuntu8_amd64.deb \
#   ./gcc-4.8-base_4.8.5-4ubuntu8_amd64.deb

# # gcc-4.8 & g++-4.8
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.8/gcc-4.8_4.8.5-4ubuntu8_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.8/g++-4.8_4.8.5-4ubuntu8_amd64.deb
# sudo apt install -y \
#   ./gcc-4.8_4.8.5-4ubuntu8_amd64.deb \
#   ./g++-4.8_4.8.5-4ubuntu8_amd64.deb

# # gcc-4.9 & g++-4.9 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.9/gcc-4.9-base_4.9.3-13ubuntu2_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/main/m/mpfr4/libmpfr4_3.1.4-1_amd64.deb
# # gcc-4.9 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.9/cpp-4.9_4.9.3-13ubuntu2_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.9/libgcc-4.9-dev_4.9.3-13ubuntu2_amd64.deb
# # g++-4.9 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.9/libstdc++-4.9-dev_4.9.3-13ubuntu2_amd64.deb
# # libgcc-4.9-dev dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.9/libasan1_4.9.3-13ubuntu2_amd64.deb

# sudo apt install -y \
#   ./libasan1_4.9.3-13ubuntu2_amd64.deb \
#   ./libstdc++-4.9-dev_4.9.3-13ubuntu2_amd64.deb \
#   ./libgcc-4.9-dev_4.9.3-13ubuntu2_amd64.deb \
#   ./cpp-4.9_4.9.3-13ubuntu2_amd64.deb \
#   ./libmpfr4_3.1.4-1_amd64.deb \
#   ./gcc-4.9-base_4.9.3-13ubuntu2_amd64.deb

# # gcc-4.9 & g++-4.9
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.9/gcc-4.9_4.9.3-13ubuntu2_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-4.9/g++-4.9_4.9.3-13ubuntu2_amd64.deb
# sudo apt install -y \
#   ./gcc-4.9_4.9.3-13ubuntu2_amd64.deb \
#   ./g++-4.9_4.9.3-13ubuntu2_amd64.deb

# FLAGS="HOSTCC=gcc-4.9 CC=gcc-4.9"

# # gcc-5 & g++-5 dependencies
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-5/gcc-5-base_5.5.19.0-12ubuntu1_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/main/i/isl/libisl15_0.16.1-1_amd64.deb
# # gcc-5 dependencies
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-5/cpp-5_5.5.19.0-12ubuntu1_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-5/libgcc-5-dev_5.5.19.0-12ubuntu1_amd64.deb \
# # g++-5 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-5/libstdc++-5-dev_5.5.19.0-12ubuntu1_amd64.deb
# # libgcc-5-dev dependencies
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-5/libasan2_5.5.19.0-12ubuntu1_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-5/libmpx0_5.5.19.0-12ubuntu1_amd64.deb
  
# sudo apt install -y \
#   ./libasan2_5.5.19.0-12ubuntu1_amd64.deb \
#   ./libmpx0_5.5.19.0-12ubuntu1_amd64.deb \
#   ./libstdc++-5-dev_5.5.19.0-12ubuntu1_amd64.deb \
#   ./libgcc-5-dev_5.5.19.0-12ubuntu1_amd64.deb \
#   ./cpp-5_5.5.19.0-12ubuntu1_amd64.deb \
#   ./libisl15_0.16.1-1_amd64.deb \
#   ./gcc-5-base_5.5.19.0-12ubuntu1_amd64.deb

# # gcc-5 & g++-5
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-5/gcc-5_5.5.19.0-12ubuntu1_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-5/g++-5_5.5.19.0-12ubuntu1_amd64.deb
# sudo apt install -y \
#   ./gcc-5_5.5.19.0-12ubuntu1_amd64.deb \
#   ./g++-5_5.5.19.0-12ubuntu1_amd64.deb

# # gcc-6 & g++-6 dependencies
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-6/gcc-6-base_6.5.0-2ubuntu1~18.04_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/main/i/isl/libisl19_0.19-1_amd64.deb
# # gcc-6 dependencies
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-6/cpp-6_6.5.0-2ubuntu1~18.04_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-6/libgcc-6-dev_6.5.0-2ubuntu1~18.04_amd64.deb
# # g++-6 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-6/libstdc++-6-dev_6.5.0-2ubuntu1~18.04_amd64.deb
# # libgcc-6-dev dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-6/libasan3_6.5.0-2ubuntu1~18.04_amd64.deb

# sudo apt install -y \
#   ./libasan3_6.5.0-2ubuntu1~18.04_amd64.deb \
#   ./libstdc++-6-dev_6.5.0-2ubuntu1~18.04_amd64.deb \
#   ./libgcc-6-dev_6.5.0-2ubuntu1~18.04_amd64.deb \
#   ./cpp-6_6.5.0-2ubuntu1~18.04_amd64.deb \
#   ./libisl19_0.19-1_amd64.deb \
#   ./gcc-6-base_6.5.0-2ubuntu1~18.04_amd64.deb

# # gcc-6 & g++-6
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-6/gcc-6_6.5.0-2ubuntu1~18.04_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-6/g++-6_6.5.0-2ubuntu1~18.04_amd64.deb
# sudo apt install -y \
#   ./gcc-6_6.5.0-2ubuntu1~18.04_amd64.deb \
#   ./g++-6_6.5.0-2ubuntu1~18.04_amd64.deb

# # gcc-7 & g++-7 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/gcc-7-base_7.5.0-6ubuntu2_amd64.deb
# # gcc-7 dependencies
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/cpp-7_7.5.0-6ubuntu2_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/libgcc-7-dev_7.5.0-6ubuntu2_amd64.deb
# # g++-7 dependency
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/libstdc++-7-dev_7.5.0-6ubuntu2_amd64.deb
# # libgcc-7-dev dependencies
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/libasan4_7.5.0-6ubuntu2_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/libubsan0_7.5.0-6ubuntu2_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/libcilkrts5_7.5.0-6ubuntu2_amd64.deb

# sudo apt install -y \
#   ./libcilkrts5_7.5.0-6ubuntu2_amd64.deb \
#   ./libubsan0_7.5.0-6ubuntu2_amd64.deb \
#   ./libasan4_7.5.0-6ubuntu2_amd64.deb \
#   ./libstdc++-7-dev_7.5.0-6ubuntu2_amd64.deb \
#   ./libgcc-7-dev_7.5.0-6ubuntu2_amd64.deb \
#   ./cpp-7_7.5.0-6ubuntu2_amd64.deb \
#   ./gcc-7-base_7.5.0-6ubuntu2_amd64.deb

# # gcc-7 & g++-7
# wget http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/gcc-7_7.5.0-6ubuntu2_amd64.deb \
#   http://archive.ubuntu.com/ubuntu/pool/universe/g/gcc-7/g++-7_7.5.0-6ubuntu2_amd64.deb
# sudo apt install -y \
#   ./gcc-7_7.5.0-6ubuntu2_amd64.deb \
#   ./g++-7_7.5.0-6ubuntu2_amd64.deb

# # gcc-8 & g++-8 dependencies
# wget http://mirrors.edge.kernel.org/ubuntu/pool/universe/g/gcc-8/gcc-8-base_8.4.0-3ubuntu2_amd64.deb \
#   http://mirrors.kernel.org/ubuntu/pool/main/i/isl/libisl22_0.22.1-1_amd64.deb
# # gcc-8 dependencies
# wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-8/cpp-8_8.4.0-3ubuntu2_amd64.deb \
#   http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-8/libgcc-8-dev_8.4.0-3ubuntu2_amd64.deb
# # g++-8 dependency
# wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-8/libstdc++-8-dev_8.4.0-3ubuntu2_amd64.deb
# # libgcc-8-dev dependency
# wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-8/libmpx2_8.4.0-3ubuntu2_amd64.deb

# sudo apt install -y \
#   ./libmpx2_8.4.0-3ubuntu2_amd64.deb \
#   ./libstdc++-8-dev_8.4.0-3ubuntu2_amd64.deb \
#   ./libgcc-8-dev_8.4.0-3ubuntu2_amd64.deb \
#   ./cpp-8_8.4.0-3ubuntu2_amd64.deb \
#   ./libisl22_0.22.1-1_amd64.deb \
#   ./gcc-8-base_8.4.0-3ubuntu2_amd64.deb

# # gcc-8 & g++-8
# wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-8/gcc-8_8.4.0-3ubuntu2_amd64.deb \
#   http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-8/g++-8_8.4.0-3ubuntu2_amd64.deb
# sudo apt install -y \
#   ./gcc-8_8.4.0-3ubuntu2_amd64.deb \
#   ./g++-8_8.4.0-3ubuntu2_amd64.deb
