# Specify the new version you want to use
PV = "3.21.12"

# Update the source revision to match the tag or commit for version 3.21.12
SRCREV = "f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c"

RPROVIDES:${PN}="protobuf"

PARALLEL_MAKE = "-j12"

INHERIT += "static-libs"

# Enable PIC for both static and shared builds
EXTRA_OECMAKE_SHARED = "-Dprotobuf_BUILD_SHARED_LIBS=ON -Dprotobuf_BUILD_STATIC_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON"
EXTRA_OECMAKE_STATIC = "-Dprotobuf_BUILD_SHARED_LIBS=OFF -Dprotobuf_BUILD_STATIC_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON"

do_compile() {
    # Configure and build the static library
    cmake ${S} -B${B} ${EXTRA_OECMAKE_STATIC}
    ninja -C ${B} ${PARALLEL_MAKE}
    find ${B} -name "libprotobuf.a"

    # Reconfigure for shared build and build shared library
    cmake ${S} -B${B} ${EXTRA_OECMAKE_SHARED}
    ninja -C ${B} ${PARALLEL_MAKE}
}

do_install:append() {
    install -d ${D}${libdir}
    if [ -f ${B}/libprotobuf.a ]; then
        install -m 0644 ${B}/libprotobuf.a ${D}${libdir}
    else
        bbwarn "libprotobuf.a not found!"
    fi
}

FILES:${PN}-staticdev += "${libdir}/libprotobuf.a"
RDEPENDS:${PN}-dev += "${PN}-staticdev"

# Ensure sysroot-staging contains the static library
SYSROOT_DIRS:append = " ${libdir}/libprotobuf.a"

