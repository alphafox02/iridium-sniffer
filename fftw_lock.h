/*
 * FFTW thread-safety wrapper.
 * FFTW plan creation is not thread-safe. All plan calls must be serialized.
 * Call fftw_lock_init() before creating any threads.
 */

#ifndef __FFTW_LOCK_H__
#define __FFTW_LOCK_H__

#include <pthread.h>

extern pthread_mutex_t fftw_planner_mutex;

static inline void fftw_lock_init(void) {
    pthread_mutex_init(&fftw_planner_mutex, NULL);
}

static inline void fftw_lock(void) {
    pthread_mutex_lock(&fftw_planner_mutex);
}

static inline void fftw_unlock(void) {
    pthread_mutex_unlock(&fftw_planner_mutex);
}

#endif
