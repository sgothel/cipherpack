/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2022 Gothel Software e.K.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "org_cipherpack_CPUtils.h"

#include <cstdint>
#include <cinttypes>

#include <time.h>

#include <jau/environment.hpp>

#include "helper_base.hpp"

static const uint64_t NanoPerMilli = 1000000UL;
static const uint64_t MilliPerOne = 1000UL;

/**
 * See <http://man7.org/linux/man-pages/man2/clock_gettime.2.html>
 * <p>
 * Regarding avoiding kernel via VDSO,
 * see <http://man7.org/linux/man-pages/man7/vdso.7.html>,
 * clock_gettime seems to be well supported at least on kernel >= 4.4.
 * Only bfin and sh are missing, while ia64 seems to be complicated.
 */
jlong Java_org_cipherpack_CPUtils_currentTimeMillis(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    uint64_t res = static_cast<uint64_t>( t.tv_sec ) * MilliPerOne +
                   static_cast<uint64_t>( t.tv_nsec ) / NanoPerMilli;
    return (jlong)res;
}

jlong Java_org_cipherpack_CPUtils_wallClockSeconds(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (jlong)( static_cast<uint64_t>( t.tv_sec ) );
}


jlong Java_org_cipherpack_CPUtils_startupTimeMillisImpl(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    return jau::environment::startupTimeMilliseconds;
}
