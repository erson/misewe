#ifndef SECURE_MEM_H
#define SECURE_MEM_H

#include <stddef.h>

/* Secure memory allocation functions */
void *secure_malloc(size_t size);
void *secure_calloc(size_t nmemb, size_t size);
void secure_free(void *ptr);
void *secure_realloc(void *ptr, size_t size);

/* Secure string functions */
size_t secure_strlen(const char *str);
char *secure_strdup(const char *str);
char *secure_strndup(const char *str, size_t n);
int secure_strcmp(const char *s1, const char *s2);
char *secure_strcpy(char *dest, const char *src, size_t size);

/* Memory wiping */
void secure_memzero(void *ptr, size_t len);
void secure_memset(void *ptr, int value, size_t len);

/* Memory protection */
void secure_lock_memory(void *ptr, size_t len);
void secure_unlock_memory(void *ptr, size_t len);

#endif /* SECURE_MEM_H */