SUMMARY = "HIP headers"
DESCRIPTION = "HIP (Heterogeneous-Computing Interface for Portability) headers for Telluride"
LICENSE = "CLOSED"
INHIBIT_LICENSE_CHECK = "1"

SRC_URI = "file://hip_headers_5_7_31921.tar.gz"
S = "${WORKDIR}"

PACKAGES = "${PN} ${PN}-dev"

do_install() {
    install -d ${D}${includedir}/hip
    cp -r ${S}/usr/include/hip/* ${D}${includedir}/hip/
}

# Headers in -dev for build-time (e.g. XRT); hip is meta package for runtime
FILES:${PN}-dev = "${includedir}/hip ${libdir}/cmake/hip"
FILES:${PN} = ""
ALLOW_EMPTY:${PN} = "1"
