#include "mpop_internal.h"


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
        /*old_iconv = iconv_open("UTF-8", mb_read_mpopd_config()->default_charset);
        assert( old_iconv != (iconv_t) - 1  );
        */
    }
    return old_iconv;
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
        printf("convert error %s");
    to->size = start - to->string;
    *start = '\0';
    return 1;
}
