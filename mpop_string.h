#ifndef _MPOP_STRING_H
#define _MPOP_STRING_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h> /* memset */
#include <unistd.h> /* close */


/* Strings */

typedef struct mpop_string
{
	char *string;
	int  size;
	int  alloc_size;
}
mpop_string;

void init_string(mpop_string *str);
void free_string(mpop_string *str);
void clear_string(mpop_string *str);
void add_char(mpop_string *str, char c);
void add_string(mpop_string *str, const char *s);
void add_stringn(mpop_string *str, const void *s, int size);
void allocate_string(mpop_string *str, int size);

static inline void add_stringn_logalloc(mpop_string *str, const char *s, int sz) {
    char *np;
    int need_size = str->size + sz + 1;
    if (need_size > str->alloc_size) {
        if (need_size < 1024) need_size = 2048;
        else need_size = (int)((double)need_size * 1.3);

        allocate_string(str, need_size);
    }
    np = str->string + str->size;
    memcpy(np, s, sz);
    np[sz] = 0;
    str->size += sz;
}

void str_vprintf(mpop_string *str, const char *fmt, va_list ap);
void str_printf(mpop_string *str, const char *fmt, ...)
		__attribute__ ((format (printf, 2, 3)));

#endif /* _MPOP_STRING_H */
