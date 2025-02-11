/*
 * GPU-accelerated burst detection FFT via OpenCL + VkFFT
 *
 * Pipeline per batch:
 *   1. Upload complex float samples to GPU
 *   2. Window multiply kernel (per-element, Blackman window)
 *   3. VkFFT batched forward FFT (in-place)
 *   4. fftshift + magnitude squared kernel
 *   5. Download magnitude floats back to CPU
 *
 * Adapted from ice9-bluetooth-sniffer opencl/fft.c pattern.
 */

#ifdef USE_OPENCL

#define CL_TARGET_OPENCL_VERSION 120

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/opencl.h>
#endif

#define VKFFT_BACKEND 3
#include "vkFFT.h"

#include "burst_fft.h"

/* ---- OpenCL kernel source ---- */

static const char *burst_kernels_source =
"__kernel void window_multiply(\n"
"    __global const float *input,\n"
"    __global const float *window,\n"
"    __global float *output,\n"
"    const int fft_size)\n"
"{\n"
"    int gid = get_global_id(0);\n"
"    int win_idx = gid % fft_size;\n"
"    float w = window[win_idx];\n"
"    output[2*gid]   = input[2*gid]   * w;\n"
"    output[2*gid+1] = input[2*gid+1] * w;\n"
"}\n"
"\n"
"__kernel void fftshift_magnitude(\n"
"    __global const float *fft_out,\n"
"    __global float *magnitude,\n"
"    const int fft_size)\n"
"{\n"
"    int gid = get_global_id(0);\n"
"    int frame = gid / fft_size;\n"
"    int bin = gid % fft_size;\n"
"    int half_n = fft_size / 2;\n"
"    int src_bin = (bin + half_n) % fft_size;\n"
"    int src_idx = frame * fft_size + src_bin;\n"
"    float re = fft_out[2*src_idx];\n"
"    float im = fft_out[2*src_idx+1];\n"
"    magnitude[gid] = re * re + im * im;\n"
"}\n";

/* ---- GPU context ---- */

struct gpu_burst_fft {
    int fft_size;
    int batch_size;

    /* OpenCL */
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kern_window;
    cl_kernel kern_magnitude;

    /* GPU buffers */
    cl_mem cl_input;        /* float [batch_size * fft_size * 2] (complex) */
    cl_mem cl_fft;          /* float [batch_size * fft_size * 2] (complex, in-place FFT) */
    cl_mem cl_magnitude;    /* float [batch_size * fft_size] */
    cl_mem cl_window;       /* float [fft_size] (uploaded once) */

    /* VkFFT */
    VkFFTApplication vkfft_app;
    uint64_t fft_buffer_size;
};

/* ---- OpenCL device discovery ---- */

static cl_device_id find_opencl_device(void) {
    cl_int err;
    cl_uint num_platforms;
    cl_platform_id platforms[16];
    cl_device_id device = 0;
    char name[256], plat_name[256];

    err = clGetPlatformIDs(16, platforms, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0)
        return 0;

    /* prefer GPU */
    for (cl_uint p = 0; p < num_platforms; p++) {
        err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 1, &device, NULL);
        if (err == CL_SUCCESS) {
            clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(name), name, NULL);
            clGetPlatformInfo(platforms[p], CL_PLATFORM_NAME,
                              sizeof(plat_name), plat_name, NULL);
            fprintf(stderr, "OpenCL GPU: %s (%s)\n", name, plat_name);
            return device;
        }
    }

    /* fall back to any device */
    for (cl_uint p = 0; p < num_platforms; p++) {
        err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, 1, &device, NULL);
        if (err == CL_SUCCESS) {
            clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(name), name, NULL);
            fprintf(stderr, "OpenCL device: %s\n", name);
            return device;
        }
    }

    return 0;
}

/* ---- Compile kernels ---- */

static int compile_kernels(gpu_burst_fft_t *g) {
    cl_int err;

    g->program = clCreateProgramWithSource(g->context, 1, &burst_kernels_source,
                                            NULL, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: create program error %d\n", err);
        return -1;
    }

    err = clBuildProgram(g->program, 1, &g->device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        char log[4096];
        clGetProgramBuildInfo(g->program, g->device, CL_PROGRAM_BUILD_LOG,
                              sizeof(log), log, NULL);
        fprintf(stderr, "OpenCL build error: %s\n", log);
        return -1;
    }

    g->kern_window = clCreateKernel(g->program, "window_multiply", &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: create window kernel error %d\n", err);
        return -1;
    }

    g->kern_magnitude = clCreateKernel(g->program, "fftshift_magnitude", &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: create magnitude kernel error %d\n", err);
        return -1;
    }

    return 0;
}

/* ---- Create ---- */

gpu_burst_fft_t *gpu_burst_fft_create(int fft_size, int batch_size,
                                       const float *window) {
    cl_int err;

    gpu_burst_fft_t *g = calloc(1, sizeof(*g));
    if (!g) return NULL;

    g->fft_size = fft_size;
    g->batch_size = batch_size;

    /* Find device */
    g->device = find_opencl_device();
    if (!g->device) {
        fprintf(stderr, "OpenCL: no device found\n");
        free(g);
        return NULL;
    }

    /* Create context and queue */
    g->context = clCreateContext(NULL, 1, &g->device, NULL, NULL, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: create context error %d\n", err);
        free(g);
        return NULL;
    }

    g->queue = clCreateCommandQueue(g->context, g->device, 0, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: create queue error %d\n", err);
        clReleaseContext(g->context);
        free(g);
        return NULL;
    }

    /* Compile kernels */
    if (compile_kernels(g) != 0) {
        clReleaseCommandQueue(g->queue);
        clReleaseContext(g->context);
        free(g);
        return NULL;
    }

    /* Allocate GPU buffers */
    size_t complex_batch_bytes = (size_t)batch_size * fft_size * 2 * sizeof(float);
    size_t mag_batch_bytes = (size_t)batch_size * fft_size * sizeof(float);
    size_t window_bytes = (size_t)fft_size * sizeof(float);

    g->cl_input = clCreateBuffer(g->context, CL_MEM_READ_ONLY,
                                  complex_batch_bytes, NULL, &err);
    if (err != CL_SUCCESS) goto err_bufs;

    g->cl_fft = clCreateBuffer(g->context, CL_MEM_READ_WRITE,
                                complex_batch_bytes, NULL, &err);
    if (err != CL_SUCCESS) goto err_bufs;

    g->cl_magnitude = clCreateBuffer(g->context, CL_MEM_WRITE_ONLY,
                                      mag_batch_bytes, NULL, &err);
    if (err != CL_SUCCESS) goto err_bufs;

    g->cl_window = clCreateBuffer(g->context, CL_MEM_READ_ONLY,
                                   window_bytes, NULL, &err);
    if (err != CL_SUCCESS) goto err_bufs;

    /* Upload window coefficients (one-time) */
    err = clEnqueueWriteBuffer(g->queue, g->cl_window, CL_TRUE, 0,
                                window_bytes, window, 0, NULL, NULL);
    if (err != CL_SUCCESS) goto err_bufs;

    /* Set static kernel arguments */
    clSetKernelArg(g->kern_window, 0, sizeof(cl_mem), &g->cl_input);
    clSetKernelArg(g->kern_window, 1, sizeof(cl_mem), &g->cl_window);
    clSetKernelArg(g->kern_window, 2, sizeof(cl_mem), &g->cl_fft);
    clSetKernelArg(g->kern_window, 3, sizeof(int), &fft_size);

    clSetKernelArg(g->kern_magnitude, 0, sizeof(cl_mem), &g->cl_fft);
    clSetKernelArg(g->kern_magnitude, 1, sizeof(cl_mem), &g->cl_magnitude);
    clSetKernelArg(g->kern_magnitude, 2, sizeof(int), &fft_size);

    /* Initialize VkFFT */
    g->fft_buffer_size = complex_batch_bytes;

    VkFFTConfiguration config = {};
    config.FFTdim = 1;
    config.size[0] = (uint64_t)fft_size;
    config.numberBatches = (uint64_t)batch_size;
    config.device = &g->device;
    config.context = &g->context;
    config.commandQueue = &g->queue;
    config.buffer = &g->cl_fft;
    config.bufferSize = &g->fft_buffer_size;

    VkFFTResult vk_res = initializeVkFFT(&g->vkfft_app, config);
    if (vk_res != VKFFT_SUCCESS) {
        fprintf(stderr, "VkFFT init error: %d\n", vk_res);
        goto err_bufs;
    }

    fprintf(stderr, "GPU burst FFT: %d-point, batch %d, VkFFT ready\n",
            fft_size, batch_size);
    return g;

err_bufs:
    fprintf(stderr, "OpenCL: buffer allocation error %d\n", err);
    if (g->cl_input) clReleaseMemObject(g->cl_input);
    if (g->cl_fft) clReleaseMemObject(g->cl_fft);
    if (g->cl_magnitude) clReleaseMemObject(g->cl_magnitude);
    if (g->cl_window) clReleaseMemObject(g->cl_window);
    clReleaseKernel(g->kern_window);
    clReleaseKernel(g->kern_magnitude);
    clReleaseProgram(g->program);
    clReleaseCommandQueue(g->queue);
    clReleaseContext(g->context);
    free(g);
    return NULL;
}

/* ---- Destroy ---- */

void gpu_burst_fft_destroy(gpu_burst_fft_t *g) {
    if (!g) return;

    deleteVkFFT(&g->vkfft_app);

    clReleaseMemObject(g->cl_input);
    clReleaseMemObject(g->cl_fft);
    clReleaseMemObject(g->cl_magnitude);
    clReleaseMemObject(g->cl_window);
    clReleaseKernel(g->kern_window);
    clReleaseKernel(g->kern_magnitude);
    clReleaseProgram(g->program);
    clReleaseCommandQueue(g->queue);
    clReleaseContext(g->context);

    free(g);
}

/* ---- Process batch ---- */

int gpu_burst_fft_process(gpu_burst_fft_t *g, const float *input,
                           float *output, int batch_count) {
    cl_int err;

    if (batch_count <= 0 || batch_count > g->batch_size)
        return -1;

    size_t complex_bytes = (size_t)batch_count * g->fft_size * 2 * sizeof(float);
    size_t mag_bytes = (size_t)batch_count * g->fft_size * sizeof(float);
    size_t work_items = (size_t)batch_count * g->fft_size;

    /* 1. Upload input samples to GPU */
    err = clEnqueueWriteBuffer(g->queue, g->cl_input, CL_FALSE, 0,
                                complex_bytes, input, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "GPU: upload error %d\n", err);
        return -1;
    }

    /* 2. Window multiply kernel */
    err = clEnqueueNDRangeKernel(g->queue, g->kern_window, 1, NULL,
                                  &work_items, NULL, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "GPU: window kernel error %d\n", err);
        return -1;
    }

    /* 3. VkFFT forward FFT (in-place on cl_fft) */
    VkFFTLaunchParams params = {};
    params.commandQueue = &g->queue;

    VkFFTResult vk_res = VkFFTAppend(&g->vkfft_app, -1, &params);
    if (vk_res != VKFFT_SUCCESS) {
        fprintf(stderr, "GPU: VkFFT error %d\n", vk_res);
        return -1;
    }

    /* 4. fftshift + magnitude kernel */
    err = clEnqueueNDRangeKernel(g->queue, g->kern_magnitude, 1, NULL,
                                  &work_items, NULL, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "GPU: magnitude kernel error %d\n", err);
        return -1;
    }

    /* 5. Download magnitude results */
    err = clEnqueueReadBuffer(g->queue, g->cl_magnitude, CL_TRUE, 0,
                               mag_bytes, output, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "GPU: download error %d\n", err);
        return -1;
    }

    return 0;
}

#endif /* USE_OPENCL */
