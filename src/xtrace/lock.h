#ifndef _XTRACE_LOCK_H_
#define _XTRACE_LOCK_H_

#include <darling/emulation/syscall/linux/ext/futex.h>
#include <stdint.h>

#include "base.h"

// we also have to implement our own locks, because we can't rely on libplatform's or libpthread's locks
// so we implement our own on top of Linux futexes

XTRACE_DECLARATIONS_C_BEGIN

//
// lock
//

typedef struct xtrace_lock {
	uint32_t state;
} xtrace_lock_t;

#define XTRACE_LOCK_INITIALIZER {0}

XTRACE_INLINE
void xtrace_lock_init(xtrace_lock_t* lock) {
	lock->state = 0;
};

void xtrace_lock_lock(xtrace_lock_t* lock);
void xtrace_lock_unlock(xtrace_lock_t* lock);

//
// once
//

typedef struct xtrace_once {
	uint32_t state;
} xtrace_once_t;

typedef void (*xtrace_once_callback)(void);

#define XTRACE_ONCE_INITIALIZER {0}

XTRACE_INLINE
void xtrace_once_init(xtrace_once_t* once) {
	once->state = 0;
};

void xtrace_once(xtrace_once_t* once, xtrace_once_callback callback);

XTRACE_DECLARATIONS_C_END

#endif // _XTRACE_LOCK_H_
