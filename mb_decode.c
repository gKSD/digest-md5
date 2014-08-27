/*
 * Copyright (C) 2001-2002 Mail.Ru
 *
 * $Id: mb_decode.c,v 1.68 2010/11/10 15:09:19 dmitriev Exp $
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <regex.h>
#include <sysexits.h>
#include <string.h>
#include <iconv.h>

#include "mailbox.h"

#ifndef lint
static const char rcsid[] = "$Id: mb_decode.c,v 1.68 2010/11/10 15:09:19 dmitriev Exp $";
#endif /* lint */

#define BASE64  1
#define QUOTED 2

static uint32_t Base64Table[] = { // Char -> base64 value
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52,
53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1,
-1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 
43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1
};

static unsigned char ToBase64Table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

void 
init_state(decoder_state * state)
{
	bzero(state, sizeof(decoder_state));
}

void 
init_encoder_state(encoder_state * state)
{
	bzero(state, sizeof(encoder_state));
}

int 
to_base64(unsigned char r, encoder_state * state, mpop_string * to)
{
	state->i++;
	state->r = (state->r << 8) | r;
	if (state->i > 2) {
		int i;
		unsigned char r;
		
		for (i=18; i>=0; i-=6) {
			if (state->line_len >= BASE64_LINE_LEN) {
				add_char(to, '\n');
				state->line_len = 0;
			}
			r = (state->r >> i) & 0x3F;
		    r = ToBase64Table[r];
			add_char(to, r);
			state->line_len ++;
		}
		state->i = 0;
	}
	return 1;
}

int 
from_base64(uint8_t r, decoder_state * state, mpop_string * to)
{
    r = (uint8_t)Base64Table[r];
    if (r == (uint8_t)-1) return 0;

    state->base.i++;
    state->base.r = (state->base.r << 6) | r;
    if (state->base.i > 3) {
        unsigned long r = state->base.r;
        const char buf[] = { (char)((r >> 16) & 0xFF), (char)((r >> 8) & 0xFF),  (char)(r & 0xFF) };
        add_stringn_logalloc(to, buf, 3);
        state->base.i = 0;
    }
	return 1;
}

static char
from_hex(char r, char *n)
{
	if ((r >= 'A') && (r <= 'F')) {
		r -= ('A' - 10);
	} else
		if ((r >= 'a') && (r <= 'f')) {
			r -= ('a' - 10);
		} else
			if ((r >= '0') && (r <= '9')) {
				r -= '0';
			} else 
				return 0;
	*n = *n << 4;
	*n |= r;
	return 1;
}

int 
encode_flush(mpop_string * to, encoder_state * state)
{
	int i;
	unsigned char r;
	
	if (state->i == 0)
		return 0;

	state->r <<= (3 - state->i) * 2;

	for (i=state->i*6; i>=0; i-=6) {
		if (state->line_len >= BASE64_LINE_LEN) {
			add_char(to, '\n');
			state->line_len = 0;
		}
		r = (state->r >> i) & 0x3F;
		r = ToBase64Table[r];
		add_char(to, r);
		state->line_len ++;
	}

	for (i=3-state->i; i>0; i--) {
		if (state->line_len >= BASE64_LINE_LEN) {
			add_char(to, '\n');
			state->line_len = 0;
		}
		add_char(to, '=');
		state->line_len ++;
	}

	return 1;
}

int 
decode_flush(mpop_string * to, decoder_state * state)
{
	
    if (state->base.i == 0) return 0;
    
    state->base.r <<= (4 - state->base.i) * 6;
	//unsigned long r = (state->base.r << 6);

	if (state->base.i > 1) {
		add_char(to, (char) ((state->base.r >> 16) & 0xFF));
	}
	if (state->base.i > 2) {
		add_char(to, (char)((state->base.r >> 8) & 0xFF));
	}
	if (state->base.i > 3 ) {
		add_char(to, (char)(state->base.r & 0xFF));
	}
	return 1;
}

void 
encode_base64(mpop_string * to, const char *from, int size, encoder_state * state)
{
	int i;

	// Preallocate because mpop.tmpl allocates 1 byte at a time, which is slow
	if (to->size + MPOP_MEM_ALLOC_GROW_STEP > to->alloc_size) allocate_string(to, to->alloc_size + MPOP_MEM_ALLOC_GROW_STEP);

	/* &encode_base64 does NOT place \n at the end of encoded string.
	 * it is important because of precise converting of total_size */
	for (i=0; i<size; i++) {
		to_base64(from[i], state, to);
	}
}

void 
decode_base64(mpop_string * to, const char *from, decoder_state * state)
{
    unsigned char *b = (unsigned char *)from;
    for (; *b; b++) 
        from_base64(*b, state, to);
}

void 
decode_quoted(mpop_string * to, const char *from, decoder_state * state)
{
	int     i;
	char    r;
	int count_spaces = 0;

	for (i = 0; from[i];) {
		r = from[i++];
		if (r == ' ' || r == '\t') {
			count_spaces++;
			add_char(to, r);

			continue;
		}

		count_spaces = 0;
		if (r == '=') {
				if (!from[i])
					break;

				if (from[i + 1]) {
					r = 0;
					if (!from_hex(from[i],&r) || !from_hex(from[i + 1], &r))
						r = '=';
					else i += 2;
				}
		} else {
			if (state->is_header && (r == '_' || r == '\n'))
				r = ' ';
		}

		add_char(to, r);
	}

	if (count_spaces) {
		to->size -= count_spaces;
		*(to->string + to->size) = '\0';
	}
}
#define DEC(c)		(((c) - ' ') & 077)
#define IS_DEC(c)	((((c) - ' ') >= 0) &&  (((c) - ' ') <= 077 + 1))

void
decode_uu(mpop_string * to, const char *from, decoder_state * statet)
{
	const char   *p = from;
	char    ch;
	int     n;
	if ((n = DEC(*p)) <= 0)
		return;
	for (++p; n > 0; p += 4, n -= 3) {
		if (n >= 3) {
			if (!(IS_DEC(*p) && IS_DEC(*(p + 1)) && IS_DEC(*(p + 2)) && IS_DEC(*(p + 3))))
				return;
			ch = DEC(p[0]) << 2 | DEC(p[1]) >> 4;
			add_char(to, ch);
			ch = DEC(p[1]) << 4 | DEC(p[2]) >> 2;
			add_char(to, ch);
			ch = DEC(p[2]) << 6 | DEC(p[3]);
			add_char(to, ch);
		} else {
			if (n >= 1) {
				if (!(IS_DEC(*p) && IS_DEC(*(p + 1))))
					return;
				ch = DEC(p[0]) << 2 | DEC(p[1]) >> 4;
				add_char(to, ch);
			}
			if (n >= 2) {
				if (!(IS_DEC(*(p + 1)) && IS_DEC(*(p + 2))))
					return;
				ch = DEC(p[1]) << 4 | DEC(p[2]) >> 2;
				add_char(to, ch);
			}
			if (n >= 3) {
				if (!(IS_DEC(*(p + 2)) && IS_DEC(*(p + 3))))
					return;
				ch = DEC(p[2]) << 6 | DEC(p[3]);
				add_char(to, ch);
			}
		}
	}
}

// All variants of BOM
typedef struct boms_s {
	const char marker[5];
	size_t length;
} boms_t;

static const boms_t bom_variants[] = {
	{{0,0,255,254},     4},
	{{221,115,102,115}, 4},
	{{239,187,191},     3},
	{{243,100,76},      3},
	{{254,255,0,0},     4}, // must be before the 2-byte variant of this marker
	{{254,255},         2},
	{{255,254},         2},
	{{43,47,118,43},    4},
	{{43,47,118,47},    4},
	{{43,47,118,56},    4},
	{{43,47,118,57},    4}
};
static const size_t bom_variants_size = sizeof(bom_variants) / sizeof(bom_variants[0]);

// Drop byte-order marker
static int drop_bom(char* str, int len) {
	if (str == NULL) return 0;

	int f;
	size_t length = len + 1;

	for (f = 0; f < bom_variants_size; f++) {
		if (length < bom_variants[f].length+1) continue;
		if (memcmp(str, bom_variants[f].marker, bom_variants[f].length) == 0) {
			// found a match
			length -= bom_variants[f].length;
			memmove(str, str+bom_variants[f].length, length);
			return bom_variants[f].length;
		}
	}
	return 0;
}

static char *parse_encoded_word(char **source, const char **charset, const char **method, const char **encoded_word)
{
	char *start_word = *source;
	char *str;

	for (str = *source; *str; str++) {
		char *p, *c, *m;

		if (*str != '=' || *(str + 1) != '?')
			continue;
		p = str++;

		p += 2;
		c = p;
		while (*p && (*p != '?')) p++;
		if (!*p) {
			// encoded word not possible further
			str = p;
			break;
		}
		// optimization
		str = p - 1;

		m = ++p;
		if (!*p || (*(++p) != '?'))
			continue;

		++p;
		while (*p && (*p != '?')) p++;
		if (!*p || (*(++p) != '='))
			continue;

		// terminate start_word
		*(c - 2) = '\0';
		// method
		*method = m;
		// terminate charset
		*charset = c;
		*(m - 1) = '\0';
		// terminate encoded_word
		*encoded_word = m + 2;
		*(p - 1) = '\0';

		str = ++p;

		break;
	}

	*source = str;

	return start_word;
}

void decode_string_to_utf8(mpop_string *str, const char *charset, size_t max_size)
{
	if (!str->string) return;
	mpop_string n;
	init_string(&n);
	decode_words_to_utf(&n, str->string, charset, max_size);
	clear_string(str);
	if (n.string) *str = n;
 }

int only_spaces_in_str(const char *str)
{
	if (!str) return 0;

	for (;*str && isspace(*str); str++) ;

	if (!*str) return 1;
	return 0;
}

static inline void save_str_in_utf8(mpop_string *from, mpop_string *to, const char *charset, iconv_t cur_iconv, int max_size)
{
	if (strcmp(charset, "utf-8"))
		iconv_to_utf8_mpop_str(cur_iconv, from->string, from->size, to, max_size);
	else
		add_stringn(to, from->string, MIN(from->size, max_size - to->size));
	clear_string(from);
}

void
decode_words_to_utf(mpop_string * to, char *str, const char * source_charset , size_t max_size)
{
    char	*from = str;
    int     i;
    char *start_word = NULL;
    const char *charset;
    const char *method;
	const char *encoded_word = from;
    char   *start_str;

	char prev_word_is_encoded = 0;
	const char *prev_charset = NULL;

	iconv_t prev_iconv = (iconv_t) - 1;
	iconv_t source_iconv = (iconv_t) - 1;
    clear_string(to);

    mpop_string b64;
    init_string(&b64);

    if (source_charset)
            source_iconv = find_iconv_charset( source_charset );

    while ( (to->size < max_size) && from && *from) {
		charset = encoded_word = NULL;
		start_word = parse_encoded_word(&from, &charset, &method, &encoded_word);

		//we assume that we can have few spaces between 2 encoded words. so if we face them we'll skip them 
		if (start_word && *start_word &&
		    !(prev_word_is_encoded && encoded_word && only_spaces_in_str(start_word))) {
			if (b64.size)
				save_str_in_utf8(&b64, to, prev_charset, prev_iconv, max_size);

			if (source_charset)
				iconv_to_utf8_mpop_str( source_iconv, start_word , strlen(start_word), to, max_size);
			else
				add_stringn(to, start_word, MIN(strlen(start_word), max_size - to->size));
			prev_word_is_encoded  = 0;
		}

		if (encoded_word && charset) {
				decoder_state st;

				charset = (const char *)get_valid_charset(charset);
				if (!prev_charset || strcmp(prev_charset, charset)) {
					if (b64.size)
						save_str_in_utf8(&b64, to, prev_charset, prev_iconv, max_size);

					if (prev_iconv != (iconv_t) -1) iconv_close(prev_iconv);
					prev_iconv = find_iconv_charset(charset);
					prev_charset = charset;
				}

				init_state(&st);
				st.is_header = true;
				if ((*method == 'b') || (*method == 'B')) {
						int old_size = b64.size;

						decode_base64(&b64, encoded_word, &st);
						decode_flush(&b64, &st);

						if (strcmp(charset, "utf16"))
							b64.size -= drop_bom(b64.string + old_size, b64.size - old_size);
				}
				else if ((*method == 'q') || (*method == 'Q'))
						decode_quoted(&b64, encoded_word, &st);

				prev_word_is_encoded = 1;
		}
	}
	if (prev_word_is_encoded && b64.size)
		save_str_in_utf8(&b64, to, prev_charset, prev_iconv, max_size);

    if (source_iconv != (iconv_t)-1)	iconv_close(source_iconv);
	if (prev_iconv != (iconv_t) - 1)	iconv_close(prev_iconv);

	free_string(&b64);
}
