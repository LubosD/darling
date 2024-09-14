#ifndef _XTRACELIB_H_
#define _XTRACELIB_H_
#include <stdint.h>
#include <darling/emulation/syscall/common/simple.h>

#include "base.h"
#include "string.h"

#ifdef XTRACE_CPP
struct calldef
{
	const char* name;
	void (*print_args)(xtrace::String* log, int nr, void* args[]);
	void (*print_retval)(xtrace::String* log, int nr, uintptr_t rv);
};

void handle_generic_entry(xtrace::String* log, const struct calldef* defs, const char* type, int nr, void* args[]);
void handle_generic_exit(xtrace::String* log, const struct calldef* defs, const char* type, uintptr_t retval, int force_split);

void xtrace_set_gray_color(xtrace::String* log);
void xtrace_reset_color(xtrace::String* log);

void xtrace_start_line(xtrace::String* log, int indent);
#endif

XTRACE_DECLARATIONS_C_BEGIN

extern int xtrace_no_color;

void xtrace_log(const char* format, ...) __attribute__((format(printf, 1, 2)));
void xtrace_log_v(const char* format, va_list args) __attribute__((format(printf, 1, 0)));
void xtrace_error(const char* format, ...) __attribute__((format(printf, 1, 2)));
void xtrace_error_v(const char* format, va_list args) __attribute__((format(printf, 1, 0)));

void xtrace_abort(const char* message) __attribute__((noreturn));

XTRACE_DECLARATIONS_C_END

#endif

