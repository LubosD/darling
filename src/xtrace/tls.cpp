#include "tls.h"
#include "memory.h"
#include "lock.h"
#include "xtracelib.h"

#include <stdlib.h>
#include <pthread/tsd_private.h>

#include <darling/emulation/syscall/common/trace/xtrace_api.h>
#include <darling/emulation/syscall/common/simple.h>

#ifndef XTRACE_TLS_DEBUG
	#define XTRACE_TLS_DEBUG 0
#endif

#if XTRACE_TLS_DEBUG
	#define xtrace_tls_debug(x, ...) xtrace_log(x "\n", ## __VA_ARGS__)
#else
	#define xtrace_tls_debug(x, ...)
#endif

// 32 TLS vars should be enough, right?
#define TLS_TABLE_MAX_SIZE 32

typedef struct tls_table* tls_table_t;
struct tls_table {
	size_t size;
	void* table[TLS_TABLE_MAX_SIZE][3];
};

// since we still need to handle some calls after pthread_terminate is called and libpthread unwinds its TLS right before calling pthread_terminate,
// we have to use a slightly hackier technique: using one of the system's reserved but unused TLS keys; we use one from the range we currently reserve
// for Darling.

#include <darling/emulation/syscall/common/darling_tsd.h>

// TODO: also perform TLS cleanup for other threads when doing a fork

extern "C"
void xtrace_tls_thread_cleanup(void) {
	tls_table_t table = (tls_table_t)_pthread_getspecific_direct(__PTK_DARLING_XTRACE_TLS);
	if (!table) {
		xtrace_tls_debug("no table to cleanup for this thread");
		return;
	}
	xtrace_tls_debug("destroying table %p", table);
	for (size_t i = 0; i < table->size; ++i) {
		if (table->table[i][2]) {
			xtrace_tls_debug("destroying value %p for key %p", table->table[i][1], table->table[i][0]);
			((xtrace_tls_destructor_f)table->table[i][2])(table->table[1]);
		}
		xtrace_tls_debug("freeing value %p for key %p", table->table[i][1], table->table[i][0]);
		xtrace_free(table->table[i][1]);
	}
	xtrace_tls_debug("freeing table %p", table);
	xtrace_free(table);
};

extern "C"
void* xtrace_tls(void* key, size_t size, bool* created, xtrace_tls_destructor_f destructor) {
	xtrace_tls_debug("looking up tls variable for key %p", key);

	tls_table_t table = (tls_table_t)_pthread_getspecific_direct(__PTK_DARLING_XTRACE_TLS);

	xtrace_tls_debug("got %p as table pointer from pthread", table);

	// if the table doesn't exist yet, create it
	if (table == NULL) {
		xtrace_tls_debug("table is NULL, creating now...");
		table = (tls_table_t)xtrace_malloc(sizeof(struct tls_table));
		if (table == NULL) {
			xtrace_abort("xtrace: failed TLS table memory allocation");
		}
		table->size = 0;
		_pthread_setspecific_direct(__PTK_DARLING_XTRACE_TLS, table);
	}

	// check if the key is already present
	for (size_t i = 0; i < table->size; ++i) {
		if (table->table[i][0] == key) {
			xtrace_tls_debug("found entry in table for key %p with value %p", key, table->table[i][1]);
			if (created) {
				*created = false;
			}
			return table->table[i][1];
		}
	}

	// otherwise, create it
	xtrace_tls_debug("creating new entry in table for key %p", key);
	size_t index = table->size++;
	if (index >= TLS_TABLE_MAX_SIZE) {
		xtrace_abort("xtrace: too many TLS variables");
	}
	table->table[index][0] = key;
	table->table[index][1] = xtrace_malloc(size);
	table->table[index][2] = (void*)destructor;
	if (table->table[index][1] == NULL) {
		xtrace_abort("xtrace: failed TLS variable memory allocation");
	}
	xtrace_tls_debug("new table entry created for key %p with value %p", key, table->table[index][1]);
	if (created) {
		*created = true;
	}
	return table->table[index][1];
};
