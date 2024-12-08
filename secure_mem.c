#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include "secure_mem.h"
#include "logger.h"

/* Memory block header */
typedef struct {
    size_t size;
    unsigned int magic;
    unsigned char canary[8];
} mem_header_t;

#define MAGIC_VALUE 0xDEADBEEF
#define CANARY_SIZE 8
#define CANARY_VALUE 0xAA

/* Initialize canary with random values */
static void init_canary(unsigned char *canary) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        fread(canary, 1, CANARY_SIZE, urandom);
        fclose(urandom);
    } else {
        /* Fallback to less secure but still useful value */
        memset(canary, CANARY_VALUE, CANARY_SIZE);
    }
}

/* Verify memory block integrity */
static int verify_block(mem_header_t *header) {
    if (header->magic != MAGIC_VALUE) {
        ERROR_LOG("Memory corruption detected: invalid magic value");
        return 0;
    }

    unsigned char *block_end = (unsigned char *)(header + 1) + header->size;
    for (int i = 0; i < CANARY_SIZE; i++) {
        if (block_end[i] != header->canary[i]) {
            ERROR_LOG("Memory corruption detected: canary mismatch");
            return 0;
        }
    }

    return 1;
}

/* Secure memory allocation */
void *secure_malloc(size_t size) {
    if (size == 0 || size > SIZE_MAX - sizeof(mem_header_t) - CANARY_SIZE) {
        ERROR_LOG("Invalid allocation size: %zu", size);
        return NULL;
    }

    /* Allocate memory with header and canary */
    size_t total_size = sizeof(mem_header_t) + size + CANARY_SIZE;
    mem_header_t *header = malloc(total_size);
    if (!header) {
        ERROR_LOG("Memory allocation failed");
        return NULL;
    }

    /* Initialize header */
    header->size = size;
    header->magic = MAGIC_VALUE;
    init_canary(header->canary);

    /* Set up canary at the end of the block */
    unsigned char *block_end = (unsigned char *)(header + 1) + size;
    memcpy(block_end, header->canary, CANARY_SIZE);

    /* Return pointer to user data */
    return header + 1;
}

/* Secure memory deallocation */
void secure_free(void *ptr) {
    if (!ptr) return;

    /* Get header */
    mem_header_t *header = ((mem_header_t *)ptr) - 1;

    /* Verify block integrity */
    if (!verify_block(header)) {
        ERROR_LOG("Attempting to free corrupted memory block");
        abort();  /* Memory corruption is a serious error */
    }

    /* Securely wipe memory */
    secure_memzero(ptr, header->size);
    secure_memzero(header->canary, CANARY_SIZE);
    header->magic = 0;

    /* Free memory */
    free(header);
}

/* Secure memory wiping that won't be optimized away */
void secure_memzero(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) {
        *p++ = 0;
    }
}

/* Secure memory comparison (constant time) */
int secure_strcmp(const char *s1, const char *s2) {
    if (!s1 || !s2) return -1;

    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    
    /* Compare lengths first */
    if (len1 != len2) return -1;

    int result = 0;
    for (size_t i = 0; i < len1; i++) {
        /* XOR differences to prevent timing attacks */
        result |= (s1[i] ^ s2[i]);
    }

    return result;
}

/* Lock memory to prevent swapping */
void secure_lock_memory(void *ptr, size_t len) {
    if (mlock(ptr, len) < 0) {
        ERROR_LOG("Failed to lock memory: %s", strerror(errno));
    }
}

/* Secure string duplication */
char *secure_strdup(const char *str) {
    if (!str) return NULL;

    size_t len = strlen(str);
    char *dup = secure_malloc(len + 1);
    if (dup) {
        memcpy(dup, str, len);
        dup[len] = '\0';
    }
    return dup;
}