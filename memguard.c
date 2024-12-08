#include "memguard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <errno.h>

/* Memory block header */
typedef struct {
    size_t size;
    unsigned int magic;
    unsigned char canary[8];
} memguard_header_t;

/* Memory block footer */
typedef struct {
    unsigned char canary[8];
} memguard_footer_t;

/* Global statistics */
static struct {
    size_t total_allocated;
    size_t current_allocated;
    size_t peak_allocated;
    size_t allocation_count;
    size_t free_count;
    pthread_mutex_t lock;
} memstats = {0};

#define MAGIC_VALUE 0xDEADBEEF
#define PAGE_SIZE 4096
#define MIN_ALLOC 32

/* Initialize memory guard */
static void __attribute__((constructor)) memguard_init(void) {
    pthread_mutex_init(&memstats.lock, NULL);
}

/* Finalize memory guard */
static void __attribute__((destructor)) memguard_fini(void) {
    pthread_mutex_destroy(&memstats.lock);
}

/* Generate random canary value */
static void generate_canary(unsigned char *canary) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        fread(canary, 1, 8, urandom);
        fclose(urandom);
    } else {
        /* Fallback to less secure but still useful value */
        for (int i = 0; i < 8; i++) {
            canary[i] = (unsigned char)(rand() & 0xFF);
        }
    }
}

/* Verify memory block integrity */
static bool verify_block(memguard_header_t *header) {
    if (header->magic != MAGIC_VALUE) {
        fprintf(stderr, "Memory corruption detected: invalid magic value\n");
        return false;
    }

    memguard_footer_t *footer = (memguard_footer_t *)
        ((char *)(header + 1) + header->size);

    if (memcmp(header->canary, footer->canary, 8) != 0) {
        fprintf(stderr, "Memory corruption detected: canary mismatch\n");
        return false;
    }

    return true;
}

/* Align size to page boundary */
static size_t align_size(size_t size) {
    return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

/* Allocate memory with protection */
void *memguard_alloc(size_t size) {
    if (size == 0 || size > SIZE_MAX - sizeof(memguard_header_t) -
                     sizeof(memguard_footer_t)) {
        return NULL;
    }

    /* Calculate total size needed */
    size_t total_size = sizeof(memguard_header_t) + size +
                       sizeof(memguard_footer_t);
    total_size = align_size(total_size);

    /* Allocate memory with guard pages */
    void *block = mmap(NULL, total_size + 2 * PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (block == MAP_FAILED) {
        return NULL;
    }

    /* Set up guard pages */
    mprotect(block, PAGE_SIZE, PROT_NONE);
    mprotect(block + total_size + PAGE_SIZE, PAGE_SIZE, PROT_NONE);

    /* Initialize header */
    memguard_header_t *header = (memguard_header_t *)
                               ((char *)block + PAGE_SIZE);
    header->size = size;
    header->magic = MAGIC_VALUE;
    generate_canary(header->canary);

    /* Initialize footer */
    memguard_footer_t *footer = (memguard_footer_t *)
                               ((char *)(header + 1) + size);
    memcpy(footer->canary, header->canary, 8);

    /* Update statistics */
    pthread_mutex_lock(&memstats.lock);
    memstats.total_allocated += size;
    memstats.current_allocated += size;
    memstats.allocation_count++;
    if (memstats.current_allocated > memstats.peak_allocated) {
        memstats.peak_allocated = memstats.current_allocated;
    }
    pthread_mutex_unlock(&memstats.lock);

    return header + 1;
}

/* Free memory */
void memguard_free(void *ptr) {
    if (!ptr) return;

    /* Get header */
    memguard_header_t *header = ((memguard_header_t *)ptr) - 1;

    /* Verify block integrity */
    if (!verify_block(header)) {
        fprintf(stderr, "Attempt to free corrupted memory block\n");
        abort();
    }

    /* Update statistics */
    pthread_mutex_lock(&memstats.lock);
    memstats.current_allocated -= header->size;
    memstats.free_count++;
    pthread_mutex_unlock(&memstats.lock);

    /* Calculate total block size */
    size_t total_size = align_size(sizeof(memguard_header_t) +
                                 header->size +
                                 sizeof(memguard_footer_t));

    /* Get block start address (before guard page) */
    void *block = (char *)header - PAGE_SIZE;

    /* Sanitize memory before freeing */
    memguard_sanitize(ptr, header->size);

    /* Unmap entire block including guard pages */
    munmap(block, total_size + 2 * PAGE_SIZE);
}

/* Change memory protection */
bool memguard_protect(void *ptr, size_t size, memguard_prot_t prot) {
    if (!ptr) return false;

    /* Convert protection flags */
    int mprot = 0;
    if (prot & MEMGUARD_READ)  mprot |= PROT_READ;
    if (prot & MEMGUARD_WRITE) mprot |= PROT_WRITE;
    if (prot & MEMGUARD_EXEC)  mprot |= PROT_EXEC;

    /* Change protection */
    return mprotect(ptr, size, mprot) == 0;
}

/* Get memory statistics */
void memguard_get_stats(memguard_stats_t *stats) {
    pthread_mutex_lock(&memstats.lock);
    stats->total_allocated = memstats.total_allocated;
    stats->current_allocated = memstats.current_allocated;
    stats->peak_allocated = memstats.peak_allocated;
    stats->allocation_count = memstats.allocation_count;
    stats->free_count = memstats.free_count;
    pthread_mutex_unlock(&memstats.lock);
}

/* Securely wipe memory */
void memguard_sanitize(void *ptr, size_t size) {
    volatile unsigned char *p = ptr;
    while (size--) {
        *p++ = 0;
    }
}