# - Find SOAPYSDR
# Find the native SoapySDR includes and library
# This module defines
#  SOAPYSDR_INCLUDE_DIR, where to find SoapySDR/Device.h, etc.
#  SOAPYSDR_LIBRARIES, the libraries needed to use SoapySDR.
#  SOAPYSDR_FOUND, If false, do not try to use SoapySDR.
# also defined, but not for general use are
#  SOAPYSDR_LIBRARY, where to find SOAPYSDR.

find_package(PkgConfig)
pkg_check_modules(PC_SOAPYSDR QUIET SoapySDR)

find_path(SOAPYSDR_INCLUDE_DIR
    NAMES SoapySDR/Device.h
    HINTS
        ${SOAPYSDR_DIR}/include
        ${PC_SOAPYSDR_INCLUDEDIR}
        ${PC_SOAPYSDR_INCLUDE_DIRS}
        /opt/homebrew/include
        /opt/local/include
        /usr/include
        /usr/local/include
)

find_library(SOAPYSDR_LIBRARY
    NAMES SoapySDR
    HINTS
        $ENV{SOAPYSDR_DIR}/lib
        ${PC_SOAPYSDR_LIBDIR}
        ${PC_SOAPYSDR_LIBRARY_DIRS}
        /opt/homebrew/lib
        /opt/local/lib
        /usr/lib
        /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SoapySDR DEFAULT_MSG SOAPYSDR_LIBRARY SOAPYSDR_INCLUDE_DIR)

if (SOAPYSDR_LIBRARY AND SOAPYSDR_INCLUDE_DIR)
    set(SOAPYSDR_LIBRARIES ${SOAPYSDR_LIBRARY})
    set(SOAPYSDR_FOUND "YES")
else ()
    set(SOAPYSDR_FOUND "NO")
endif ()

if (SOAPYSDR_FOUND)
    if (NOT SOAPYSDR_FIND_QUIETLY)
        message(STATUS "Found SoapySDR: ${SOAPYSDR_LIBRARIES}")
    endif ()
else ()
    if (SOAPYSDR_FIND_REQUIRED)
        message(FATAL_ERROR "Could not find SoapySDR library")
    endif ()
endif ()

mark_as_advanced(
    SOAPYSDR_LIBRARY
    SOAPYSDR_INCLUDE_DIR
)

set(SOAPYSDR_INCLUDE_DIRS ${SOAPYSDR_INCLUDE_DIR})
set(SOAPYSDR_LIBRARIES ${SOAPYSDR_LIBRARY})
