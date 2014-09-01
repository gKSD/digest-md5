#ifndef INCLUDED_MAILBOX_H
#define INCLUDED_MAILBOX_H
/* @file
 * Mailbox structures
 */

/*
 * including some static variable into a .h file is bad idea, but
 * this will help us detecting improper builds
 */
#ifndef lint
static const char mailbox_h_rcsid[] = "$Id: mailbox.h,v 1.187 2010/11/25 08:47:46 dmitriev Exp $";
#endif /* lint */

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h> // for bool

#include "mpop_string.h"
#include "mpop_internal.h"

#if HAVE_STRING_H
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#define MPOP_MEM_ALLOC_GROW_STEP  16384
#define MPOP2_API_VERSION 1
#define MPOP_STORAGE_PATH_MAX   128
extern int mpopd_timeout;

#define BASE64_LINE_LEN		76	/* MUST be divisible by 4! 
					 * Otherwise total_size converting expressions become inexact */
#define BINARY_LINE_LEN		(BASE64_LINE_LEN*3/4)

    /* macroses for new mbox total_size which is 64bit now */
#define b32_to_kb32(s)	((uint32_t)( ((s)+1023)>>10 ))
#define b64_to_kb32(s)	((uint32_t)( (s)>>42 ? -1 : b32_to_kb32(s) )) /// @bug signed and unsigned type in conditional expression
#define kb32_to_b32(s)	((uint32_t)( (s)>>22 ? -1 : (s)<<10 ))
#define kb32_to_b64(s)	((uint64_t)( (uint64_t)(s)<<10 ))

/* ����� ��������� */
/* ________________________________________________________________________________________ */

#define CODE_UUENCODE	1
#define CODE_BASE64	2
#define CODE_QUOTED	3
#define CODE_BINARY	4
#define CODE_DEFLATE 5
/* ________________________________________________________________________________________ */

    typedef struct encoder_state {
            unsigned r;
            unsigned i;
	    unsigned line_len;
    }       encoder_state;

    typedef union decoder_state {
    	bool is_header;

        struct base {
            unsigned r;
            unsigned i;
        }       base;
    }       decoder_state;


    void    init_state(decoder_state * state);

    void    init_encoder_state(encoder_state * state);
    void    decode_uu(mpop_string * to, const char *from, decoder_state * state);
    void    decode_quoted(mpop_string * to, const char *from, decoder_state * state);
    void    decode_base64(mpop_string * to, const char *from, decoder_state * state);
    void    encode_base64(mpop_string * to, const char *from, int size, encoder_state * state);
    int       encode_flush(mpop_string * to, encoder_state * state);
    int       decode_flush(mpop_string * to, decoder_state * state);

/* _________________________________________________________________________________________ */

#endif /* GET_INCL_VER */
