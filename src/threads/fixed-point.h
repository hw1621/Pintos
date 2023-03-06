#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#define Q_DEFAULT 14
#define FORMATTER (1 << Q_DEFAULT)

typedef int32_t fp;

// Convert int to fix point
inline fp int_to_fp (int n) {
    return n * FORMATTER;
}

// Convert x to integer (rounding toward zero)
inline int fp_to_int_0 (fp n) {
    return n / FORMATTER;
}

// Convert x to integer (rounding to nearest) 
inline int fp_to_int_nearest (fp n) {
    return n >= 0 ? (n + FORMATTER / 2) / FORMATTER 
                     : (n - FORMATTER / 2) / FORMATTER;
}

// Fix point multiply fix point
inline fp fp_mult_fp (fp n, fp m) {
    return ((int64_t) n) * m / FORMATTER;
}

// Fix point divide by fix point
inline fp fp_div_fp (fp n, fp m) {
    return ((int64_t) n) * FORMATTER / m;
}

#endif