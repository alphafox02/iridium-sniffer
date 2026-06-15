cmake_minimum_required(VERSION 3.9)
project(iridium-sniffer C)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules" ${CMAKE_MODULE_PATH})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-common -Wall -Wextra -Wno-unused-parameter -std=c99 -Werror=implicit-function-declaration")

set(GPU_PLUGIN_NAME "libiridium-sniffer-gpu.so")

if(UNIX AND NOT APPLE)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
    # ARM/AArch64: compiler handles NEON automatically
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse4.1")
  endif()
endif()

# Include paths for MacOS/Homebrew
if(APPLE)
    set(GPU_PLUGIN_NAME "libiridium-sniffer-gpu.dylib")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
        link_directories(/opt/homebrew/lib)
        include_directories(/opt/homebrew/include)
    else()
        link_directories(/usr/local/lib)
        include_directories(/usr/local/include)
    endif()
endif()

set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -g3 -O0 -fsanitize=address")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -ggdb3 -g3")
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Build RelWithDebInfo by default
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
      "Choose the type of build: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif()

# Required dependencies
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(FFTW REQUIRED)

# SDR backends (all optional, need at least one for live capture)
find_package(HackRF)
find_package(BladeRF)
find_package(UHD)
find_package(SoapySDR)
find_package(SDRplay)
find_package(Sidekiq)

# Normalize found variables (FindHackRF has a bug where LIBHACKRF_FOUND isn't set)
if(LIBHACKRF_LIBRARY AND LIBHACKRF_INCLUDE_DIR)
    set(LIBHACKRF_FOUND TRUE)
    set(LIBHACKRF_LIBRARIES ${LIBHACKRF_LIBRARY})
    set(LIBHACKRF_INCLUDE_DIRS ${LIBHACKRF_INCLUDE_DIR})
endif()

set(HAVE_ANY_SDR FALSE)
if(LIBHACKRF_FOUND OR LIBBLADERF_FOUND OR UHD_FOUND OR SOAPYSDR_FOUND OR SDRPLAY_FOUND OR SIDEKIQ_FOUND)
    set(HAVE_ANY_SDR TRUE)
endif()

if(NOT HAVE_ANY_SDR)
    message(WARNING "No SDR backend found. Live capture will not be available.\n"
                    "Install at least one of: libhackrf, libbladeRF, UHD, SoapySDR, SDRplay API, Sidekiq SDK")
endif()

# Optional ZMQ for multi-consumer PUB/SUB output (iridium-toolkit compatible)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBZMQ QUIET libzmq)
endif()
if(NOT LIBZMQ_FOUND)
    find_library(LIBZMQ_LIB zmq)
    find_path(LIBZMQ_INC zmq.h)
    if(LIBZMQ_LIB AND LIBZMQ_INC)
        set(LIBZMQ_FOUND TRUE)
        set(LIBZMQ_LIBRARIES ${LIBZMQ_LIB})
        set(LIBZMQ_INCLUDE_DIRS ${LIBZMQ_INC})
    endif()
endif()

# Optional libacars-2 for ARINC-622/ADS-C/CPDLC decoding in ACARS messages
if(PkgConfig_FOUND)
    pkg_check_modules(LIBACARS QUIET libacars-2)
endif()
if(NOT LIBACARS_FOUND)
    find_library(LIBACARS_LIB acars-2)
    find_path(LIBACARS_INC libacars/libacars.h PATH_SUFFIXES libacars-2)
    if(LIBACARS_LIB AND LIBACARS_INC)
        set(LIBACARS_FOUND TRUE)
        set(LIBACARS_LIBRARIES ${LIBACARS_LIB})
        set(LIBACARS_INCLUDE_DIRS ${LIBACARS_INC})
    endif()
endif()

# Optional GPU acceleration for burst detection FFTs (mutually exclusive)
find_package(OpenCL QUIET)
find_package(Vulkan QUIET)

if(OpenCL_FOUND)
    set(OPENCL_DEFAULT ON)
else()
    set(OPENCL_DEFAULT OFF)
endif()

# On macOS, OpenCL is deprecated since 10.14 — it is a thin Metal shim with
# high per-dispatch overhead that benchmarks slower than the NEON CPU path on
# Apple Silicon.  Disable it by default.  Override with -DUSE_OPENCL=ON.
if(APPLE AND OPENCL_DEFAULT)
    message(STATUS "OpenCL deprecated on macOS — disabled by default. Override with -DUSE_OPENCL=ON.")
    set(OPENCL_DEFAULT OFF)
endif()

option(USE_OPENCL "Use OpenCL GPU acceleration for burst detection" ${OPENCL_DEFAULT})
option(USE_VULKAN "Use Vulkan GPU acceleration for burst detection" OFF)

if(USE_OPENCL AND USE_VULKAN)
    message(FATAL_ERROR "USE_OPENCL and USE_VULKAN are mutually exclusive. Choose one.")
endif()

configure_file(${PROJECT_SOURCE_DIR}/config.h.in ${PROJECT_BINARY_DIR}/config.h)

# Sources
include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})

set(SOURCES
    ${PROJECT_SOURCE_DIR}/main.c
    ${PROJECT_SOURCE_DIR}/options.c
    ${PROJECT_SOURCE_DIR}/burst_detect.c
    ${PROJECT_SOURCE_DIR}/burst_downmix.c
    ${PROJECT_SOURCE_DIR}/qpsk_demod.c
    ${PROJECT_SOURCE_DIR}/fir_filter.c
    ${PROJECT_SOURCE_DIR}/frame_output.c
    ${PROJECT_SOURCE_DIR}/frame_decode.c
    ${PROJECT_SOURCE_DIR}/ida_decode.c
    ${PROJECT_SOURCE_DIR}/gsmtap.c
    ${PROJECT_SOURCE_DIR}/web_map.c
    ${PROJECT_SOURCE_DIR}/doppler_pos.c
    ${PROJECT_SOURCE_DIR}/sbd_acars.c
    ${PROJECT_SOURCE_DIR}/window_func.c
    ${PROJECT_SOURCE_DIR}/simd_generic.c
    ${PROJECT_SOURCE_DIR}/vita49.c
    ${PROJECT_SOURCE_DIR}/sigmf.c
    ${PROJECT_SOURCE_DIR}/cJSON.c
    ${PROJECT_SOURCE_DIR}/aircraft_db.c
    ${PROJECT_SOURCE_DIR}/basestation.c
    ${PROJECT_SOURCE_DIR}/waypoint_db.c
    ${PROJECT_SOURCE_DIR}/voice_decode.c
    ${PROJECT_SOURCE_DIR}/codec/ambe.c
    ${PROJECT_SOURCE_DIR}/codec/ecc.c
    ${PROJECT_SOURCE_DIR}/codec/frame.c
    ${PROJECT_SOURCE_DIR}/codec/math.c
    ${PROJECT_SOURCE_DIR}/codec/synth.c
    ${PROJECT_SOURCE_DIR}/codec/tables.c
    ${PROJECT_SOURCE_DIR}/codec/tone.c
)

# SIMD kernels — platform-specific, runtime-detected
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|x86|i[3-6]86")
    # x86: SSE4.2 and AVX2+FMA tiers, each compiled with their ISA flags.
    # simd_init() probes CPUID at startup and selects the best available tier.
    set_source_files_properties(${PROJECT_SOURCE_DIR}/simd_sse42.c
        PROPERTIES COMPILE_FLAGS "-msse4.2")
    set_source_files_properties(${PROJECT_SOURCE_DIR}/simd_avx2.c
        PROPERTIES COMPILE_FLAGS "-mavx2 -mfma")
    list(APPEND SOURCES
        ${PROJECT_SOURCE_DIR}/simd_sse42.c
        ${PROJECT_SOURCE_DIR}/simd_avx2.c)
    message(STATUS "SIMD: SSE4.2 + AVX2+FMA kernels enabled (runtime-detected)")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
    # AArch64: NEON is part of the base ISA, always present.
    # No extra compile flags required; <arm_neon.h> is unconditionally available.
    list(APPEND SOURCES 
        ${PROJECT_SOURCE_DIR}/simd_neon.c)
    message(STATUS "SIMD: NEON kernels enabled (AArch64)")
else()
    message(STATUS "SIMD: scalar only (unrecognised platform)")
endif()

# SDR backends
if(LIBHACKRF_FOUND)
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/hackrf.c)
    include_directories(${LIBHACKRF_INCLUDE_DIR})
endif()
if(LIBBLADERF_FOUND)
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/bladerf.c)
    include_directories(${LIBBLADERF_INCLUDE_DIR})
endif()
if(UHD_FOUND)
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/usrp.c)
    include_directories(${UHD_INCLUDE_DIR})
endif()
if(SOAPYSDR_FOUND)
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/soapysdr.c)
    include_directories(${SOAPYSDR_INCLUDE_DIR})
endif()
if(SDRPLAY_FOUND)
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/sdrplay.c)
    include_directories(${SDRPLAY_INCLUDE_DIR})
endif()
if(SIDEKIQ_FOUND)
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/sidekiq.c)
    include_directories(${SIDEKIQ_INCLUDE_DIR})
endif()

add_executable(iridium-sniffer ${SOURCES})

# Link required libraries
target_link_libraries(iridium-sniffer PRIVATE
    Threads::Threads
    m
    FFTW::Float
)
include_directories(${FFTW_INCLUDE_DIR})

# Link SDR backends
if(LIBHACKRF_FOUND)
    target_link_libraries(iridium-sniffer PRIVATE ${LIBHACKRF_LIBRARIES})
    target_compile_definitions(iridium-sniffer PRIVATE HAVE_HACKRF)
    message(STATUS "HackRF: enabled")
endif()
if(LIBBLADERF_FOUND)
    target_link_libraries(iridium-sniffer PRIVATE ${LIBBLADERF_LIBRARIES})
    target_compile_definitions(iridium-sniffer PRIVATE HAVE_BLADERF)
    message(STATUS "BladeRF: enabled")
endif()
if(UHD_FOUND)
    target_link_libraries(iridium-sniffer PRIVATE ${UHD_LIBRARIES})
    target_compile_definitions(iridium-sniffer PRIVATE HAVE_UHD)
    message(STATUS "USRP (UHD): enabled")
endif()
if(SOAPYSDR_FOUND)
    target_link_libraries(iridium-sniffer PRIVATE ${SOAPYSDR_LIBRARIES})
    target_compile_definitions(iridium-sniffer PRIVATE HAVE_SOAPYSDR)
    message(STATUS "SoapySDR: enabled")
endif()
if(SDRPLAY_FOUND)
    target_link_libraries(iridium-sniffer PRIVATE ${SDRPLAY_LIBRARIES})
    target_compile_definitions(iridium-sniffer PRIVATE HAVE_SDRPLAY)
    message(STATUS "SDRplay: enabled (native API)")
endif()
if(SIDEKIQ_FOUND)
    target_link_libraries(iridium-sniffer PRIVATE ${SIDEKIQ_LIBRARIES})
    target_compile_definitions(iridium-sniffer PRIVATE HAVE_SIDEKIQ)
    message(STATUS "Sidekiq: enabled (native libsidekiq)")
endif()

# libacars ARINC-622 decoding
if(LIBACARS_FOUND)
    target_link_libraries(iridium-sniffer PRIVATE ${LIBACARS_LIBRARIES})
    target_include_directories(iridium-sniffer PRIVATE ${LIBACARS_INCLUDE_DIRS})
    if(LIBACARS_LIBRARY_DIRS)
        target_link_directories(iridium-sniffer PRIVATE ${LIBACARS_LIBRARY_DIRS})
    endif()
    target_compile_definitions(iridium-sniffer PRIVATE HAVE_LIBACARS)
    message(STATUS "libacars: enabled (ARINC-622/ADS-C/CPDLC decoding)")
else()
    message(STATUS "libacars: not found (basic ACARS only)")
endif()

# ZMQ PUB/SUB output
if(LIBZMQ_FOUND)
    target_link_libraries(iridium-sniffer PRIVATE ${LIBZMQ_LIBRARIES})
    target_include_directories(iridium-sniffer PRIVATE ${LIBZMQ_INCLUDE_DIRS})
    target_compile_definitions(iridium-sniffer PRIVATE HAVE_ZMQ)
    message(STATUS "ZMQ: enabled (multi-consumer PUB/SUB output)")
else()
    message(STATUS "ZMQ: not found (install libzmq3-dev for --zmq support)")
endif()

# GPU acceleration - build as plugin (.so) loaded at runtime via dlopen
target_link_libraries(iridium-sniffer PRIVATE ${CMAKE_DL_LIBS})

if(USE_OPENCL AND OpenCL_FOUND)
    add_library(iridium-sniffer-gpu SHARED ${PROJECT_SOURCE_DIR}/opencl/burst_fft.c)
    target_include_directories(iridium-sniffer-gpu PRIVATE
        "${PROJECT_SOURCE_DIR}/vkfft" "${PROJECT_SOURCE_DIR}/opencl")
    target_compile_definitions(iridium-sniffer-gpu PRIVATE VKFFT_BACKEND=3 USE_OPENCL)
    target_link_libraries(iridium-sniffer-gpu PRIVATE OpenCL::OpenCL)
    set_target_properties(iridium-sniffer-gpu PROPERTIES
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
    install(TARGETS iridium-sniffer-gpu DESTINATION lib)
    message(STATUS "GPU acceleration: OpenCL (plugin)")
elseif(USE_VULKAN AND Vulkan_FOUND)
    # glslang is required for VkFFT Vulkan shader compilation
    find_library(GLSLANG_LIB glslang)
    find_library(SPIRV_LIB SPIRV)
    find_library(GLSLANG_RES_LIB glslang-default-resource-limits)
    find_library(MACHINEINDEP_LIB MachineIndependent)
    find_library(GENERICCODEGEN_LIB GenericCodeGen)
    find_library(OSDEPENDENT_LIB OSDependent)
    find_library(SPIRV_TOOLS_LIB SPIRV-Tools)
    find_library(SPIRV_TOOLS_OPT_LIB SPIRV-Tools-opt)
    find_path(GLSLANG_INCLUDE_DIR glslang_c_interface.h
              PATH_SUFFIXES glslang/Include glslang)

    if(NOT GLSLANG_LIB OR NOT SPIRV_LIB)
        message(WARNING "glslang not found, Vulkan GPU acceleration disabled.\n"
                        "Install: sudo apt install glslang-dev")
    else()
        add_library(iridium-sniffer-gpu SHARED ${PROJECT_SOURCE_DIR}/vulkan/burst_fft.c)
        target_include_directories(iridium-sniffer-gpu PRIVATE
            "${PROJECT_SOURCE_DIR}/vkfft" "${PROJECT_SOURCE_DIR}/opencl")
        if(GLSLANG_INCLUDE_DIR)
            target_include_directories(iridium-sniffer-gpu PRIVATE ${GLSLANG_INCLUDE_DIR})
        endif()
        target_compile_definitions(iridium-sniffer-gpu PRIVATE VKFFT_BACKEND=0 USE_VULKAN)
        target_link_libraries(iridium-sniffer-gpu PRIVATE Vulkan::Vulkan
                              ${GLSLANG_LIB} ${SPIRV_LIB})
        if(GLSLANG_RES_LIB)
            target_link_libraries(iridium-sniffer-gpu PRIVATE ${GLSLANG_RES_LIB})
        endif()
        if(MACHINEINDEP_LIB)
            target_link_libraries(iridium-sniffer-gpu PRIVATE ${MACHINEINDEP_LIB})
        endif()
        if(GENERICCODEGEN_LIB)
            target_link_libraries(iridium-sniffer-gpu PRIVATE ${GENERICCODEGEN_LIB})
        endif()
        if(OSDEPENDENT_LIB)
            target_link_libraries(iridium-sniffer-gpu PRIVATE ${OSDEPENDENT_LIB})
        endif()
        if(SPIRV_TOOLS_OPT_LIB)
            target_link_libraries(iridium-sniffer-gpu PRIVATE ${SPIRV_TOOLS_OPT_LIB})
        endif()
        if(SPIRV_TOOLS_LIB)
            target_link_libraries(iridium-sniffer-gpu PRIVATE ${SPIRV_TOOLS_LIB})
        endif()
        # glslang is C++, need stdc++ for linking
        target_link_libraries(iridium-sniffer-gpu PRIVATE stdc++)
        set_target_properties(iridium-sniffer-gpu PROPERTIES
            C_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON)
        install(TARGETS iridium-sniffer-gpu DESTINATION lib)
        message(STATUS "GPU acceleration: Vulkan (plugin)")
    endif()
else()
    message(STATUS "GPU acceleration: disabled (no plugin built)")
endif()

set_property(TARGET iridium-sniffer PROPERTY C_STANDARD 99)
set_property(TARGET iridium-sniffer PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

install(TARGETS iridium-sniffer DESTINATION bin)

# CPack packaging (make package)
set(CPACK_PACKAGE_NAME "iridium-sniffer")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Iridium burst detector and demodulator")
set(CPACK_PACKAGE_VENDOR "CEMAXECUTER LLC")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_GENERATOR "DEB;TGZ")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "CEMAXECUTER LLC")
set(CPACK_DEBIAN_PACKAGE_SECTION "hamradio")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
include(CPack)

# uninstall target
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
