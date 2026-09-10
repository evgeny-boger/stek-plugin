#!/bin/sh
# Build CryptoPro's pycades module against an installed CSP 5.0 R2
# (5.0.12000) + cades 2.0.15700 without root.  Needs: cmake, g++, python3-dev,
# libboost-dev (headers only), the pycades.zip sources and the
# lsb-cprocsp-devel_5.0.12000-6_all.deb from the CSP distribution.
#
#   sh tools/pycades/build.sh /path/to/pycades.zip /path/to/lsb-cprocsp-devel_5.0.12000-6_all.deb
#
# Patches applied on top of the vendor CMakeLists.txt (tools/pycades/CMakeLists.txt):
#  * headers taken from the extracted devel .deb (no sudo needed);
#  * stub/cpcsp/visibility.h supplies CPRO_PUBLIC_API and NS_SHARED_PTR=std,
#    which the 2.0.15700 cades headers expect from a newer CSP devel package
#    (libcppcades exports std::shared_ptr signatures — see `nm -DC`);
#  * pycades sources switched from boost::shared_ptr to std::shared_ptr;
#  * STL headers force-included before the CryptoPro Windows-compat headers,
#    whose SAL macro `__out` otherwise breaks <algorithm>;
#  * libcplib/libcapi10/libcapi20/librdrsup linked explicitly (CBlob symbols).
set -e
ZIP=${1:?pycades.zip}
DEVEL=${2:?lsb-cprocsp-devel deb}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$(mktemp -d)}
PY_INC=${PY_INC:-$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["include"])')}
cd "$WORK"
unzip -o -q "$ZIP"
SRC=$(ls -d pycades_*)
mkdir -p devel && dpkg-deb -x "$DEVEL" devel
cp "$HERE/CMakeLists.txt" "$SRC/CMakeLists.txt"
cp -r "$HERE/stub" "$SRC/stub"
DEV="$WORK/devel/opt/cprocsp/include"
sed -i "s#@PY_INC@#$PY_INC#; s#@DEV@#$DEV#g; s#@STUB@#$WORK/$SRC/stub#" "$SRC/CMakeLists.txt"
cd "$SRC"
sed -i 's/boost::shared_ptr/std::shared_ptr/g; s/boost::dynamic_pointer_cast/std::dynamic_pointer_cast/g; s#"boost/shared_ptr.hpp"#<memory>#' *.cpp *.h
mkdir -p build && cd build && cmake .. && make -j"$(nproc)"
SITE=$(python3 -m site --user-site)
mkdir -p "$SITE" && cp ../pycades.so "$SITE/"
python3 -c 'import pycades; print("pycades", pycades.ModuleVersion(), "installed in", pycades.__file__)'
