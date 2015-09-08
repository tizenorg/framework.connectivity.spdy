#ifndef SPDY_SETUP_H
#define SPDY_SETUP_H

#ifdef HAVE_CONFIG_H
#include "spdy_config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
typedef unsigned int uint32_t;
#endif

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif

/*
 * 'bool' exists on platforms with <stdbool.h>, i.e. C99 platforms.
 * On non-C99 platforms there's no bool, so define an enum for that.
 * On C99 platforms 'false' and 'true' also exist. Enum uses a
 * global namespace though, so use bool_false and bool_true.
 */

#ifndef HAVE_BOOL_T
typedef enum {
	bool_false = 0,
	bool_true  = 1
} bool;

/*
 * Use a define to let 'true' and 'false' use those enums.
 */
#  define false bool_false
#  define true  bool_true
#  define HAVE_BOOL_T
#endif

/* TODO: these should be made to use the callbacks if set */
#define CALLOC(phys,size) (calloc)(1, size)
#define MALLOC(phys,size) (malloc)(size)
#define REALLOC(phys,ptr,size) (realloc)(ptr, size)
#define FREE(phys, ptr) if(ptr) (free)(ptr)
#define FREEIF(ptr) if(ptr) (free)(ptr)
#define ALLOC(size) (malloc)(size)

#define STRDUP(str)	((str) ? strdup(str) : NULL)
#define STRLEN(str)	((str) ? strlen(str) : 0)
#define STRCMP(str1, str2)			((str1 && str2) ? strcmp(str1, str2) : -1)
#define STRNCPY(dest, src, size)	\
	do { \
		if(src != NULL && dest != NULL && size > 0) \
		{	\
			strncpy(dest,src,size); \
		}	\
	}while(0);

#define STRCPY(dest, src)	\
	do { \
		if(src != NULL && dest != NULL) \
		{	\
			strcpy(dest,src); \
		}	\
	}while(0);

#if 0
#define malloc _dont_use_malloc_directly
#define calloc _dont_use_calloc_directly
#define realloc _dont_use_realloc_directly
#define free _dont_use_free_directly
#endif

#endif /* SPDY_SETUP_H */
