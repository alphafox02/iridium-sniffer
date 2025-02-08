cmake_minimum_required(VERSION 3.9)
project(iridium-sniffer C)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules" ${CMAKE_MODULE_PATH})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-common -Wall -Wextra -Wno-unused-parameter -std=c99 -Werror=implicit-function-declaration")
if(UNIX AND NOT APPLE)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
    # ARM/AArch64: compiler handles NEON automatically
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse4.1")
  endif()
endif()

set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -g3 -O0 -fsanitize=address")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -ggdb3 -g3")
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")

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

# Normalize found variables (FindHackRF has a bug where LIBHACKRF_FOUND isn't set)
if(LIBHACKRF_LIBRARY AND LIBHACKRF_INCLUDE_DIR)
    set(LIBHACKRF_FOUND TRUE)
    set(LIBHACKRF_LIBRARIES ${LIBHACKRF_LIBRARY})
    set(LIBHACKRF_INCLUDE_DIRS ${LIBHACKRF_INCLUDE_DIR})
endif()

set(HAVE_ANY_SDR FALSE)
if(LIBHACKRF_FOUND OR LIBBLADERF_FOUND OR UHD_FOUND OR SOAPYSDR_FOUND)
    set(HAVE_ANY_SDR TRUE)
endif()

if(NOT HAVE_ANY_SDR)
    message(WARNING "No SDR backend found. Live capture will not be available.\n"
                    "Install at least one of: libhackrf, libbladeRF, UHD, SoapySDR")
endif()

# Optional GPU acceleration for burst detection FFTs (mutually exclusive)
find_package(OpenCL QUIET)
find_package(Vulkan QUIET)

if(OpenCL_FOUND)
    set(OPENCL_DEFAULT ON)
else()
    set(OPENCL_DEFAULT OFF)
endif()

option(USE_OPENCL "Use OpenCL GPU acceleration for burst detection" ${OPENCL_DEFAULT})
option(USE_VULKAN "Use Vulkan GPU acceleration for burst detection" OFF)

if(USE_OPENCL AND USE_VULKAN)
    message(FATAL_ERROR "USE_OPENCL and USE_VULKAN are mutually exclusive. Choose one.")
endif()

# Sources
include_directories(${PROJECT_SOURCE_DIR})

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
    ${PROJECT_SOURCE_DIR}/window_func.c
)

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

# GPU acceleration
if(USE_OPENCL AND OpenCL_FOUND)
    target_sources(iridium-sniffer PRIVATE ${PROJECT_SOURCE_DIR}/opencl/burst_fft.c)
    include_directories("vkfft" "opencl")
    add_definitions(-DVKFFT_BACKEND=3 -DUSE_OPENCL -DUSE_GPU)
    target_link_libraries(iridium-sniffer PRIVATE OpenCL::OpenCL)
    message(STATUS "GPU acceleration: OpenCL")
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
        target_sources(iridium-sniffer PRIVATE ${PROJECT_SOURCE_DIR}/vulkan/burst_fft.c)
        include_directories("vkfft" "opencl")  # opencl/ has burst_fft.h
        if(GLSLANG_INCLUDE_DIR)
            include_directories(${GLSLANG_INCLUDE_DIR})
        endif()
        add_definitions(-DVKFFT_BACKEND=0 -DUSE_VULKAN -DUSE_GPU)
        target_link_libraries(iridium-sniffer PRIVATE Vulkan::Vulkan
                              ${GLSLANG_LIB} ${SPIRV_LIB})
        if(GLSLANG_RES_LIB)
            target_link_libraries(iridium-sniffer PRIVATE ${GLSLANG_RES_LIB})
        endif()
        if(MACHINEINDEP_LIB)
            target_link_libraries(iridium-sniffer PRIVATE ${MACHINEINDEP_LIB})
        endif()
        if(GENERICCODEGEN_LIB)
            target_link_libraries(iridium-sniffer PRIVATE ${GENERICCODEGEN_LIB})
        endif()
        if(OSDEPENDENT_LIB)
            target_link_libraries(iridium-sniffer PRIVATE ${OSDEPENDENT_LIB})
        endif()
        if(SPIRV_TOOLS_OPT_LIB)
            target_link_libraries(iridium-sniffer PRIVATE ${SPIRV_TOOLS_OPT_LIB})
        endif()
        if(SPIRV_TOOLS_LIB)
            target_link_libraries(iridium-sniffer PRIVATE ${SPIRV_TOOLS_LIB})
        endif()
        # glslang is C++, need stdc++ for linking
        target_link_libraries(iridium-sniffer PRIVATE stdc++)
        message(STATUS "GPU acceleration: Vulkan")
    endif()
else()
    message(STATUS "GPU acceleration: disabled")
endif()

set_property(TARGET iridium-sniffer PROPERTY C_STANDARD 99)
set_property(TARGET iridium-sniffer PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

install(TARGETS iridium-sniffer DESTINATION bin)

# uninstall target
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
