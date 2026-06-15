# - Find Epiq Solutions Sidekiq SDK (libsidekiq)
# Find the native libsidekiq includes and static library.
# This module defines
#  SIDEKIQ_INCLUDE_DIR, where to find sidekiq_api.h, etc.
#  SIDEKIQ_LIBRARIES, the libraries needed to use libsidekiq.
#  SIDEKIQ_FOUND, If false, do not try to use libsidekiq.
#
# The Sidekiq SDK ships an arch/toolchain-suffixed static archive
# (e.g. libsidekiq__x86_64.gcc.a, libsidekiq__aarch64.gcc.a). Set
# -DSIDEKIQ_DIR=/path/to/sidekiq_sdk to point at a non-standard install.

find_path(SIDEKIQ_INCLUDE_DIR
    NAMES sidekiq_api.h
    HINTS
        ${SIDEKIQ_DIR}/inc
        ${SIDEKIQ_DIR}/include
        $ENV{SIDEKIQ_DIR}/inc
        $ENV{SIDEKIQ_DIR}/include
        /opt/sidekiq/inc
        /usr/include
        /usr/local/include
)

# Static archive carries an arch.toolchain suffix; try the common ones plus a
# plain unsuffixed name in case the install provides a symlink.
find_library(SIDEKIQ_LIBRARY
    NAMES
        sidekiq__x86_64.gcc
        sidekiq__aarch64.gcc
        sidekiq__arm_cortex-a9.gcc
        sidekiq
    HINTS
        ${SIDEKIQ_DIR}/lib
        $ENV{SIDEKIQ_DIR}/lib
        /opt/sidekiq/lib
        /usr/lib
        /usr/local/lib
        /usr/lib/x86_64-linux-gnu
        /usr/lib/aarch64-linux-gnu
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sidekiq DEFAULT_MSG
    SIDEKIQ_LIBRARY SIDEKIQ_INCLUDE_DIR)

if (SIDEKIQ_LIBRARY AND SIDEKIQ_INCLUDE_DIR)
    set(SIDEKIQ_FOUND TRUE)
    # The static libsidekiq archive pulls in these companion libraries.
    # glib-2.0 is optional depending on SDK build; link it when present.
    find_library(SIDEKIQ_USB_LIBRARY NAMES usb-1.0)
    set(SIDEKIQ_LIBRARIES ${SIDEKIQ_LIBRARY})
    if (SIDEKIQ_USB_LIBRARY)
        list(APPEND SIDEKIQ_LIBRARIES ${SIDEKIQ_USB_LIBRARY})
    endif()
    list(APPEND SIDEKIQ_LIBRARIES rt m dl pthread)
else()
    set(SIDEKIQ_FOUND FALSE)
endif()

set(SIDEKIQ_INCLUDE_DIRS ${SIDEKIQ_INCLUDE_DIR})

mark_as_advanced(
    SIDEKIQ_LIBRARY
    SIDEKIQ_USB_LIBRARY
    SIDEKIQ_INCLUDE_DIR
)
