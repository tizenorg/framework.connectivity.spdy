#ifndef SPDY_LOG_H_
#define SPDY_LOG_H_

#include <stdio.h>


#define DEBUG
#ifdef DEBUG

/**
 * fprintf logging macro for libspdy.
 */
#define SPDYDEBUG(msg, arg...) \
	fprintf(stderr, "%s:%d: " msg "\n", __FUNCTION__, __LINE__, ##arg);
#else
#define SPDYDEBUG(msg, arg...)
#endif

#ifdef USE_ASSERT
#include <assert.h>
#define ASSERT_RET_VAL(cond, val) assert(cond)
#define ASSERT_RET(cond) assert(cond)
#define ASSERT(cond) assert(cond)
#else
#define ASSERT_RET_VAL(cond, val) do {\
	if (!(cond)) {\
		SPDYDEBUG("**********FAILED*******************");\
		return val;\
	}\
} while(0);

#define ASSERT_RET(cond) do {\
	if (!(cond)) {\
		SPDYDEBUG("**********FAILED*******************");\
		return;\
	}\
} while(0);

#define ASSERT(cond) do {\
	if (!(cond)) {\
		SPDYDEBUG("**********FAILED*******************");\
	}\
} while(0);
#endif

#endif
