#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * Growable byte-vector backed by PSRAM when available (with a fall back to
 * internal heap). Used to replace the historical `static T arr[MAX_*];`
 * caches scattered across the firmware so that variable-cardinality lists
 * (scan results, sniffer APs, ARP hosts, ...) no longer have an arbitrary
 * upper bound -- they grow until PSRAM is exhausted, at which point the
 * affected `dynvec_push` returns NULL and the caller logs a drop.
 *
 * Storage strategy:
 *   - First allocation: `heap_caps_realloc(NULL, n, MALLOC_CAP_SPIRAM)`.
 *   - Fall back to `realloc()` (internal heap) when PSRAM is absent or full.
 *   - Growth: `cap = max(cap*2, requested, 8)`.
 *
 * Concurrency: not thread-safe. Callers must hold the relevant module mutex.
 */

typedef struct {
    void   *data;
    size_t  count;
    size_t  cap;
    size_t  elem_size;
} dynvec_t;

bool   dynvec_init(dynvec_t *v, size_t elem_size, size_t initial_cap);
void   dynvec_free(dynvec_t *v);
void   dynvec_clear(dynvec_t *v);
bool   dynvec_reserve(dynvec_t *v, size_t need);

/**
 * Append a copy of `*elem` to the vector (must be `elem_size` bytes).
 * Returns a pointer to the in-vector slot, or NULL on OOM.
 * If `elem` is NULL the slot is zero-initialised.
 */
void  *dynvec_push(dynvec_t *v, const void *elem);

/**
 * Returns a mutable pointer to the i-th element, or NULL if out of range.
 */
void  *dynvec_at(const dynvec_t *v, size_t i);
