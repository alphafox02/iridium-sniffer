/*
 * Window function generation
 */

#include <math.h>
#include "window_func.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

void blackman_window(float *w, int n) {
    for (int i = 0; i < n; i++) {
        w[i] = 0.42f - 0.5f * cosf(2.0f * (float)M_PI * i / (n - 1))
                      + 0.08f * cosf(4.0f * (float)M_PI * i / (n - 1));
    }
}
