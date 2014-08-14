/*
 * Copyright (C) 2001-2003 Mail.Ru
 *
 * $Id: mb_utf8_util.c,v 1.7 2010/11/17 09:27:21 dmitriev Exp $
 */
#include <sys/types.h>
#include <errno.h>
#include <err.h>
#include <iconv.h>
#include <sys/param.h>
#include <assert.h>
#include "mailbox.h"
#include "sindex.h"

#include "mpop.h"
#include "mb_util.h"
#include "mpop_internal.h"
#include "mr_strings.h"

#define NMAX 35
static const char *valid_charset_names[][NMAX] = {
	{"koi8-r", "koi8_r", "koi-8-r", "koi-8", "koi-8r", "koi", "KOI8-WIN", "KOI88-R", NULL},
	{"koi8-u", "koi8_u", "koi-8-u", "koi-8u", NULL},
	{"cp1251", "windows-1251", "x-windows-1251", "windows1251", "x-windows1251", "win",
	 "win1251", "win-1251", "x-win1251", "x-win-1251", "cp-1251", "x-cp1251", "x-cp-1251",
	 "ansi", "windows-125", "1WINDOWS-1251", "windows-1251", "WINDOWS-CYRILLIC-1251",
	 "WINDOWS-1251CP1251", "WIN1251", "WINDOWDS-1251", "1251", "WINDOWS-CP1251", "WINDOWS-1251-R",
	 "WINDOWS-1251N", "WINDOW-1251", "WINDOWS", "WINDOWS-1351","WINDOWS-1252HTTP-EQUIVCONTENT-T",
	 "windows-1251", "WIN-1251-1", "WINDOWS=1251", "windows-12", "WINDOWS-1251-1", NULL},
	{"ibm866", "ibm-866", "csibm866", "866", "cp866", "cp-866", "x-cp866", "x-cp-866",
	 "x-ibm866", "x-ibm-866", "alt", "dos", NULL},
	{"iso_8859-5", "iso-8859-5:1998", "iso-8859.5", "iso_8859-5", "iso8859-5", "iso8859.5", "iso",
	 "iso-ir-144", "cyrillic", NULL},
	{"iso-8859-8", "iso-8859-8-i", NULL},//add more alias
	{"maccyrillic", "x-mac-cyrillic", "x-mac-cyr", "x-ru-mac", "x-rumac", "mac-cyr", "maccyr",
	 "ru-mac", "rumac", "mac", NULL},
	{"utf-8", "utf8", "utf", "unicode-1-1-utf-8", "utf-8mime-version", "utf-84",
	 "UTF-8HTTP-EQUIVCONTENT-TYPE", "UTF-84.3.9", "UFT-8", "UTF_8", NULL},
	{"utf-7", "unicode-1-1-utf-7", NULL},
	{"utf16", "utf-16", NULL},
	{"translit", NULL},
	{"iso-2022-jp", NULL},
	{"gb18030", "gb3212", "gb2312", NULL},
	{"cp949", "ks_c_5601-1987", "ks", "KSC5601", NULL},
	{"ASCII", "ASCII-8BIT", NULL},
	{NULL}
};

const char *get_valid_charset(const char *input_charset)
{
	if (input_charset == NULL) return NULL;

	int index = 0;
	int i = 0;
	const char *cur;
	for (index = 0; valid_charset_names[index][0]; index++) {
		for (i = 0, cur = valid_charset_names[index][i]; cur; cur = valid_charset_names[index][++i]) {
			if (!strcasecmp(cur, input_charset))
				return valid_charset_names[index][0];
		}
	}
	return input_charset;
}

iconv_t
find_iconv_charset( const char * source_charset )
{
	const char* valid_charset = get_valid_charset(source_charset);
    iconv_t old_iconv = iconv_open("UTF-8//IGNORE", valid_charset);
    if( old_iconv == (iconv_t) -1 )
    {
        warn("can't find iconv code table %s", valid_charset );
        old_iconv = iconv_open("UTF-8", mb_read_mpopd_config()->default_charset);
        assert( old_iconv != (iconv_t) - 1  );
    }
    return old_iconv;
}

int
iconv_to_utf8( iconv_t cd , char *inbuf, int inbuflen, char **to, size_t max_outsize )
{
    size_t result = 0;
    size_t outbuflen = MIN( inbuflen * 6, max_outsize );
    size_t inlen = inbuflen;
    char *out = (char *)calloc(1, outbuflen + 1);
    assert(out);
    *to = out;
    char *in = inbuf;
    if(cd == (iconv_t) -1 ){
        strncpy( out, inbuf, outbuflen +1);
        out[outbuflen] = 0;
        return 1;
    }
    result = iconv( cd, &in, &inlen, &out, &outbuflen);
    if(result == (size_t)-1 && errno != EINVAL) // EINVAL means "incomplete multibyte sequence has been encountered in the input.", we can ignore that
        warn("convert error %s", strerror(errno));
    *(out) = 0;
    return 1;
}

size_t iconv_cp1251_to_utf8_ignore_invalid_char( char *in, size_t in_len, char **out )
{
	size_t outbuflen = in_len * 6;
	size_t inlen = in_len;
	size_t iter = 0;
	char *out_buf = (char *)calloc( 1, outbuflen + 1);
	*out = out_buf;
	iconv_t cd = iconv_open( "UTF-8", "CP1251" );
	char *in_tmp = in;
	while( inlen+1 > iter){
	    if( iconv( cd, (char**) &in_tmp, &inlen, (char**) &out_buf, &outbuflen ) && outbuflen )
	    {
		iter++;
	        *in_tmp = '?';
	        warn( "%s(): ICONV: failed with error: %s", __func__, strerror( errno ) );
	        continue;
	    }

	    break;
	}
	iconv_close( cd );
	*out_buf = 0;
	return (out_buf - (*out) );
}

size_t iconv_cp1251_to_utf8( const char *in, size_t in_len, char **out )
{
    size_t outbuflen = in_len * 6;
    size_t inlen = in_len;
    char *out_tmp = (char *)calloc( 1, outbuflen + 1);
    *out = out_tmp;
    const char *in_tmp = in;
    iconv_t cd = iconv_open( "UTF-8", "CP1251" );
    if( iconv( cd, (char**) &in_tmp, &inlen, (char**) &out_tmp, &outbuflen ) )
    {
        warn( "%s(): ICONV: failed with error: %s.", __func__, strerror( errno ) );
    }
    iconv_close( cd );
    *out_tmp = 0;
    return (out_tmp - (*out) );
}

size_t iconv_utf8_to_cp1251( const char *in, size_t in_len, char **out )
{
    size_t outbuflen = in_len ;                                                                                                                                                                        
    size_t inlen = in_len;                                                                                                                                                                                
    char *out_tmp = (char *)calloc( 1, outbuflen + 1);                                                                                                                                                    
    *out = out_tmp;                                                                                                                                                                                       
    const char *in_tmp = in;
    iconv_t cd = iconv_open( "CP1251", "UTF-8" );
    if( iconv( cd, (char**) &in_tmp, &inlen, (char**) &out_tmp, &outbuflen ) )
    {
        warn( "%s(): ICONV: failed with error: %s.", __func__, strerror( errno ) );
    }
    iconv_close( cd );
    *out_tmp = 0;
    return (out_tmp - (*out));
}

size_t iconv_utf8_to_cp1251_replace_invalid_char( char *in, size_t in_len, char **out, char replacement)
{
	size_t outbuflen = in_len + 2;
	size_t inlen = in_len;
	char *out_buf = (char *)calloc( 1, outbuflen + 1);
	*out = out_buf;
	iconv_t cd = iconv_open( "CP1251", "UTF-8" );
	char *in_tmp = in;
	int iter = 0;
	while( iter < 1000 )
	{
	    if( iconv( cd, (char**) &in_tmp, &inlen, (char**) &out_buf, &outbuflen ) && outbuflen )
	    {
            if (!replacement) {
    	        *in_tmp = '?';
    	        warn( "%s(): ICONV: failed with error: %s", __func__, strerror( errno ) );
	            iter++;
            } else {
                *in_tmp = replacement;
            }
	        continue;
	    }

	    break;
	}
	iconv_close( cd );
	*out_buf = 0;
	return (out_buf - (*out) );
}

size_t iconv_utf8_to_cp1251_ignore_invalid_char( char *in, size_t in_len, char **out )
{
    return iconv_utf8_to_cp1251_replace_invalid_char(in, in_len, out, 0);
}

msg_header_t *
convert_header_to( msg_header_t * mh , int to_charset)
{
    msg_header_t * to = (msg_header_t *)calloc(1, (to_charset == CH_UTF ? (2 * mh->hv1.h.ulLength) :  mh->hv1.h.ulLength) + sizeof(MSGHEADER_V2) );
    int sizeh = mh->hv1.h.ulType >= CHUNK_MESSAGE_V2 ? sizeof(MSGHEADER_V2)  : sizeof(MSGHEADER);
    
    memcpy( to, mh, sizeh );
    
    char *info = (char *)mh + sizeh;
    char *infoTo = (char *)to + sizeof(msg_header_t);
    uint32_t sizeInfoTo = sizeof(msg_header_t) + 1;
    int32_t y = 0; 
    for(y=0; y<9; y++ ) {
        char *out = NULL; 
        if( mh->hv1.str_pos[y] ) {
            int sz = to_charset == CH_UTF ? iconv_cp1251_to_utf8(info, strlen(info), &out ) : iconv_utf8_to_cp1251(info, strlen(info), &out);
            if(out && sz) {
                sz = strlen(out) + 1;
                to->hv1.str_pos[y] = sz;
                strcpy(infoTo, out);
                infoTo += sz;
                sizeInfoTo += sz;
                free(out);
            }
        }
        if(!out) to->hv1.str_pos[y] = 0;
        info += mh->hv1.str_pos[y];
    }
    
    if( info < ((char *)mh) + mh->hv1.h.ulLength )
    {
        int sz = strlen(info) + 1;
        strcpy(infoTo, info);
        info += sz;
        infoTo += sz;
        sizeInfoTo += sz;
    } else { // null recepient
        infoTo += 1;
        sizeInfoTo += 1;
    }
    
    if( mh->hv1.h.ulType >= CHUNK_MESSAGE_V2 )
    {
        if(mh->hv2.str_pos_v2) 
        {
            to->hv2.str_pos_v2 = infoTo - (char *)to;
            info = (char *)mh + mh->hv2.str_pos_v2;
            uint32_t i = 0;
            for( ; i < mh->hv2.str_count_v2; i++ )
            {
                char t = *info;
                ++info;
                *(char *)infoTo++ = t;
                
                char *out = NULL;
                
                int sz = to_charset == CH_UTF ? iconv_cp1251_to_utf8( info, strlen(info), &out ) : iconv_utf8_to_cp1251(info, strlen(info), &out);
                if(sz > 0 && out) {
                        info += strlen(info) + 1;
                        sz = strlen(out) + 1;
                        strcpy(infoTo, out);
                        infoTo += sz;
                        sizeInfoTo += sz + sizeof(char);
                }else{
                    sz = strlen(info) + 1;
                    memcpy( infoTo, info, sz );
                    info += sz;
                    infoTo += sz;
                    sizeInfoTo += sz + sizeof(char);
                }
                free(out);
            }
        }
    }
    to->hv1.h.ulType = to_charset == CH_UTF ? CHUNK_MESSAGE_V3 : CHUNK_MESSAGE_V2;
    to->hv1.h.ulLength = sizeInfoTo;
    return to;
}

int iconv_to_utf8_mpop_str( iconv_t cd , char *inbuf, int inbuflen, mpop_string *to, size_t max_outsize )
{
    size_t result = 0;
    size_t outbuflen;
    inbuflen <<= 2;
    if (to->size + inbuflen  < max_outsize) 
        outbuflen = inbuflen;
    else 
        outbuflen = max_outsize - to->size;

    inbuflen >>= 2;
    size_t inlen = inbuflen;

    if(cd == (iconv_t) -1 ){
        int copy_size =  outbuflen < inbuflen ? outbuflen : inbuflen;
        add_stringn(to, inbuf, copy_size);
        return 1;
    }
    allocate_string(to, to->size + outbuflen + 1);
    char *in = inbuf;
    char *start = to->string + to->size;
    result = iconv( cd, &in, &inlen, &start, &outbuflen);
    if(result == (size_t)-1 && errno != EINVAL) // EINVAL means "incomplete multibyte sequence has been encountered in the input.", we can ignore that
        warn("convert error %s", strerror(errno));
    to->size = start - to->string;
    *start = '\0';
    return 1;
}
