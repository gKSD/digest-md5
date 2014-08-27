#ifndef MPOP_INTERNAL_H
#define MPOP_INTERNAL_H

#include <sys/types.h>
#include <errno.h>
#include <err.h>
#include <iconv.h>
#include <sys/param.h>
#include <assert.h>

#include "mpop_string.h"


int iconv_to_utf8_mpop_str( iconv_t cd , char *inbuf, int inbuflen, mpop_string *to, size_t max_outsize );
void decode_words_to_utf(mpop_string * to, char *str, const char * source_charset , size_t max_size);
iconv_t find_iconv_charset( const char * source_charset );
const char *get_valid_charset(const char *input_charset);
#endif

