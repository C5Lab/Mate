#include "dynvec.h"

#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"

/* Try PSRAM first so the bulk of cached data lives outside the cramped
 * internal DRAM that wifi/lwip/httpd compete for. heap_caps_realloc with a
 * NULL pointer behaves like heap_caps_malloc; with a non-NULL pointer it
 * preserves contents. On boards without PSRAM the SPIRAM caps allocation
 * returns NULL and we fall through to the standard realloc (internal). */
static void *psram_realloc(void *ptr, size_t bytes)
{
    void *p = heap_caps_realloc(ptr, bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = realloc(ptr, bytes);
    return p;
}

bool dynvec_init(dynvec_t *v, size_t elem_size, size_t initial_cap)
{
    if (!v || elem_size == 0) return false;
    v->data      = NULL;
    v->count     = 0;
    v->cap       = 0;
    v->elem_size = elem_size;
    if (initial_cap == 0) return true;
    return dynvec_reserve(v, initial_cap);
}

void dynvec_free(dynvec_t *v)
{
    if (!v) return;
    free(v->data);
    v->data  = NULL;
    v->count = 0;
    v->cap   = 0;
}

void dynvec_clear(dynvec_t *v)
{
    if (!v) return;
    v->count = 0;
}

bool dynvec_reserve(dynvec_t *v, size_t need)
{
    if (!v || v->elem_size == 0) return false;
    if (need <= v->cap) return true;

    size_t new_cap = v->cap ? v->cap : 8;
    while (new_cap < need) {
        size_t doubled = new_cap * 2;
        if (doubled <= new_cap) return false;
        new_cap = doubled;
    }

    void *p = psram_realloc(v->data, new_cap * v->elem_size);
    if (!p) return false;
    v->data = p;
    v->cap  = new_cap;
    return true;
}

void *dynvec_push(dynvec_t *v, const void *elem)
{
    if (!v) return NULL;
    if (v->count == v->cap && !dynvec_reserve(v, v->count + 1)) return NULL;

    void *slot = (char *)v->data + v->count * v->elem_size;
    if (elem) memcpy(slot, elem, v->elem_size);
    else      memset(slot, 0, v->elem_size);
    v->count++;
    return slot;
}

void *dynvec_at(const dynvec_t *v, size_t i)
{
    if (!v || i >= v->count) return NULL;
    return (char *)v->data + i * v->elem_size;
}
