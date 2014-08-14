/* $Id: mb_str.c,v 1.13 2008/10/28 15:04:05 init Exp $ */


#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>

#include "mpop_string.h"

void init_string(mpop_string *str)
{
  memset(str, 0, sizeof(mpop_string));
}

void free_string(mpop_string *str)
{
  if (str->string) free(str->string);
  init_string(str);
}

void clear_string(mpop_string *str)
{
  if (str->string) *str->string  = 0;
  str->size = 0;
}

void allocate_string(mpop_string *str, int need_size)
{
  if (str->alloc_size <= need_size)
  {
    str->alloc_size = (need_size + 255) & ~255;
    if (str->string)
    {
      str->string = (char*)realloc(str->string, str->alloc_size);
    }
    else
    {
      str->string = (char*)malloc(str->alloc_size);
      *str->string = 0;
    }
    assert(str->string!=NULL);
  }
}

void add_stringn(mpop_string *str, const void *p, int n)
{
  char *np;
  
  assert( p && str );

  allocate_string(str, str->size + n + 1);
  np = str->string + str->size;
  memcpy(np, p, n);
  np[n] = 0;
  str->size += n;
}

void add_string(mpop_string *str, const char *p)
{
  add_stringn(str, p, strlen(p));
}

void add_char(mpop_string *str, char c)
{
  add_stringn(str, &c, 1);
}

void str_vprintf(mpop_string *str, const char *fmt, va_list ap)
{
  for (; *fmt; fmt++){
	  if (*fmt == '%'){
		  int ok = 1;
		  unsigned n_fmt = 1;
		  unsigned p_prec = 0;
		  char c;
		  for (;;n_fmt++){
			c = fmt[n_fmt];
			if ((c != '#') && (c != '-') && (c != '+') && (c != ' ') && (c != '0')) break;
		  }
		  for (;;n_fmt++){
			c = fmt[n_fmt];
			if ((c < '0') || (c > '9')) break;
		  }
		  if (c == '*'){
			n_fmt++;
			c = fmt[n_fmt];
		  }
		  if (c == '.'){
			n_fmt++;
			p_prec = n_fmt;
			for (;;n_fmt++){
				c = fmt[n_fmt];
				if ((c < '0') || (c > '9')) break;
			}
		  }
		  switch (c){
		  case '%':
			add_char(str, '%');
			break;
		  case 's':{
			  char *s = va_arg(ap, char *);
			  unsigned prec = 0;
			  if (p_prec) prec = atol(fmt + p_prec);
			  if (s){
				unsigned size = strlen(s);
				if (prec && (prec < size)) size = prec;
				add_stringn(str, s, size);
			  }
			  break;
			}
		  case 'c':{
			  char c = va_arg(ap, int);
			  add_char(str, c);
			  break;
			}
		  case 'd':
		  case 'u':
		  case 'o':
		  case 'x':
		  case 'X':
		  case 'f':
		  case 'e':
		  case 'E':
		  case 'g':
		  case 'G':
		  case 'i':{
			  char buff[64];
			  char *format = (char*)malloc(n_fmt + 2);
			  memcpy(format, fmt, n_fmt+1);
			  format[n_fmt+1] = 0;
			  snprintf(buff, sizeof(buff), format, va_arg(ap, int));
			  free(format);
			  add_string(str, buff);
			  break;
			}
		  default:
			  ok = 0;
		  }
		  if (ok){
			fmt += n_fmt;
			continue;
		  }
	  }
	  add_char(str, *fmt);
  }
}

void str_printf(mpop_string *str, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  str_vprintf(str, fmt, ap);
  va_end(ap);
}

