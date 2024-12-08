#ifndef MEMGUARD_H
#define MEMGUARD_H

#include <stddef.h>
#include <stdbool.h>

/* Memory protection flags */
typedef enum {
    MEMGUARD_READ = 1 << 0,
    MEMGUARD_WRITE = 1 << 1,
    MEMGUARD_EXEC = 1 << 2
} memguard_prot_t;

/* Memory statistics */
typedef struct {
    size_t total_allocated;
    size_t current_allocated;
    size_t peak_allocated;
    size_t allocation_count;
    size_t free_count;
} memguard_stats_t;

/* Function prototypes */
void *memguard_alloc(size_t size);
void *memguard_calloc(size_t nmemb, size_t size);
void memguard_free(void *ptr);
bool memguard_protect(void *ptr, size_t size, memguard_prot_t prot);
void memguard_get_stats(memguard_stats_t *stats);
void memguard_sanitize(void *ptr, size_t size);

#endif /* MEMGUARD_H */