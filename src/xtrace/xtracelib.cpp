#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <darling/emulation/syscall/common/simple.h>
#include "xtracelib.h"
#include "mig_trace.h"
#include "tls.h"
#include "lock.h"
#include "memory.h"
#include <limits.h>

#include <darling/emulation/syscall/common/trace/xtrace_api.h>
#include <fcntl.h>
#include <signal.h>

// Defined in assembly
extern "C" void darling_mach_syscall_entry_trampoline(void);
extern "C" void darling_mach_syscall_exit_trampoline(void);
extern "C" void darling_bsd_syscall_entry_trampoline(void);
extern "C" void darling_bsd_syscall_exit_trampoline(void);
extern "C" int sys_thread_selfid(void);

static void xtrace_thread_exit_hook(void);
static void xtrace_execve_inject_hook(const char*** envp_ptr);
static void xtrace_postfork_child_hook(void);

#ifdef __x86_64__
struct hook {
	uint8_t movabs[2];
	uint64_t addr;
	uint8_t call[3];
} __attribute__((packed));
#elif defined(__i386__)
struct hook {
	uint8_t mov;
	uint32_t addr;
	uint8_t call[2];
} __attribute__((packed));
#else
#error "Missing hook struct for arch"
#endif

// Defined in libsystem_kernel
extern struct hook* _darling_mach_syscall_entry;
extern struct hook* _darling_mach_syscall_exit;
extern struct hook* _darling_bsd_syscall_entry;
extern struct hook* _darling_bsd_syscall_exit;

extern "C" void _xtrace_thread_exit(void);
extern "C" void _xtrace_execve_inject(const char*** envp_ptr);
extern "C" void _xtrace_postfork_child(void);

static void xtrace_setup_mach(void);
static void xtrace_setup_bsd(void);
static void setup_hook(struct hook* hook, void* fnptr, bool jump);
static void xtrace_setup_options(void);
static void xtrace_setup_misc_hooks(void);

static int xtrace_ignore = 1;

// whether to use a sigaltstack guard page below the stack
// (this should probably be left on)
#define SIGALTSTACK_GUARD 1

__attribute__((constructor))
extern "C"
void xtrace_setup()
{
	xtrace_setup_options();
	xtrace_setup_mig_tracing();
	xtrace_setup_mach();
	xtrace_setup_bsd();
	xtrace_setup_misc_hooks();

	// override the default sigaltstack used by libsystem_kernel for the main thread
	// (we need more than the default 8KiB; testing has shown that 16KiB seems to be enough)
	struct bsd_stack custom_altstack = {
		.ss_size = 16 * 1024,
		.ss_flags = 0,
	};

#if SIGALTSTACK_GUARD
	custom_altstack.ss_sp = (void*)mmap(NULL, custom_altstack.ss_size + 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (custom_altstack.ss_sp == MAP_FAILED) {
		xtrace_abort("xtrace: failed to allocate larger sigstack for main thread");
	}

	mprotect(custom_altstack.ss_sp, 4096, PROT_NONE);
	custom_altstack.ss_sp = (char*)custom_altstack.ss_sp + 4096;
#else
	custom_altstack.ss_sp = (void*)mmap(NULL, custom_altstack.ss_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (custom_altstack.ss_sp == MAP_FAILED) {
		xtrace_abort("xtrace: failed to allocate larger sigstack for main thread");
	}
#endif

	if (_sigaltstack_for_xtrace(&custom_altstack, NULL) < 0) {
		xtrace_abort("failed to override sigaltstack");
	}

	// and set the size to allocate for future threads
	_sigaltstack_set_default_size_for_xtrace(custom_altstack.ss_size);

	xtrace_ignore = 0;
}

static int xtrace_split_entry_and_exit = 0;
int xtrace_no_color = 0;
int xtrace_kprintf = 0;

static int xtrace_use_logfile = 0;
static int xtrace_use_per_thread_logfile = 0;

static char xtrace_logfile_base[PATH_MAX] = {0};

static xtrace_once_t xtrace_common_logfile_once = XTRACE_ONCE_INITIALIZER;
int xtrace_common_logfile = -1;

static void xtrace_per_thread_logfile_destroy(int* ptr) {
	if (xtrace_use_per_thread_logfile && ptr && *ptr >= 0) {
		_close_for_xtrace(*ptr);
	}
};

DEFINE_XTRACE_TLS_VAR(int, xtrace_per_thread_logfile, -1, xtrace_per_thread_logfile_destroy);

static bool string_is_truthy(const char* string) {
	return string && (string[0] == '1' || string[0] == 'T' || string[0] == 't' || string[0] == 'Y' || string[0] == 'y');
};

static void xtrace_setup_options(void)
{
	const char* xtrace_log_file = getenv("XTRACE_LOG_FILE");

	xtrace_split_entry_and_exit = string_is_truthy(getenv("XTRACE_SPLIT_ENTRY_AND_EXIT"));
	xtrace_no_color = string_is_truthy(getenv("XTRACE_NO_COLOR"));
	xtrace_kprintf = string_is_truthy(getenv("XTRACE_KPRINTF"));
	xtrace_use_per_thread_logfile = string_is_truthy(getenv("XTRACE_LOG_FILE_PER_THREAD"));

	if (xtrace_log_file != NULL && xtrace_log_file[0] != '\0') {
		xtrace_use_logfile = 1;
		strlcpy(xtrace_logfile_base, xtrace_log_file, sizeof(xtrace_logfile_base));
	}
}


static void setup_hook(struct hook* hook, void* fnptr, bool jump)
{
#if defined(__x86_64__)
	// this hook is (in GAS syntax):
	//   movq $<fnptr value>, %r10
	//   call *%r10
	// the call turns to a jump if `jump` is true
	hook->movabs[0] = 0x49;
	hook->movabs[1] = 0xba;
	hook->call[0] = 0x41;
	hook->call[1] = 0xff;
	hook->call[2] = jump ? 0xe2 : 0xd2;
	hook->addr = (uintptr_t)fnptr;
#elif defined(__i386__)
	// this hook is (in GAS syntax):
	//   mov $<fnptr value>, %ecx
	//   call *%ecx
	// the call turns into a jump if `jump` is true
	hook->mov = 0xb9;
	hook->addr = (uintptr_t)fnptr;
	hook->call[0] = 0xff;
	hook->call[1] = jump ? 0xe1 : 0xd1;
#else
#error "Missing hook implementation for arch
#endif
}

static void xtrace_setup_mach(void)
{
	uintptr_t area = (uintptr_t)_darling_mach_syscall_entry;
	uintptr_t areaEnd = ((uintptr_t)_darling_mach_syscall_exit) + sizeof(struct hook);

	// __asm__("int3");
	area &= ~(4096-1);
	areaEnd &= ~(4096-1);

	uintptr_t bytes = 4096 + (areaEnd-area);

	mprotect((void*) area, bytes, PROT_READ | PROT_WRITE | PROT_EXEC);

	setup_hook(_darling_mach_syscall_entry, (void*)darling_mach_syscall_entry_trampoline, false);
	setup_hook(_darling_mach_syscall_exit, (void*)darling_mach_syscall_exit_trampoline, false);

	mprotect((void*) area, bytes, PROT_READ | PROT_EXEC);
}

static void xtrace_setup_bsd(void)
{
	uintptr_t area = (uintptr_t)_darling_bsd_syscall_entry;
	uintptr_t areaEnd = ((uintptr_t)_darling_bsd_syscall_exit) + sizeof(struct hook);

	// __asm__("int3");
	area &= ~(4096-1);
	areaEnd &= ~(4096-1);

	uintptr_t bytes = 4096 + (areaEnd-area);

	mprotect((void*) area, bytes, PROT_READ | PROT_WRITE | PROT_EXEC);

	setup_hook(_darling_bsd_syscall_entry, (void*)darling_bsd_syscall_entry_trampoline, false);
	setup_hook(_darling_bsd_syscall_exit, (void*)darling_bsd_syscall_exit_trampoline, false);

	mprotect((void*) area, bytes, PROT_READ | PROT_EXEC);
}

// like setup_hook, but also takes care of making memory writable for the hook setup and restoring it afterwards
static void setup_hook_with_perms(struct hook* hook, void* fnptr, bool jump) {
	uintptr_t area = (uintptr_t)hook;
	uintptr_t areaEnd = ((uintptr_t)hook) + sizeof(struct hook);

	// __asm__("int3");
	area &= ~(4096-1);
	areaEnd &= ~(4096-1);

	uintptr_t bytes = 4096 + (areaEnd-area);

	mprotect((void*) area, bytes, PROT_READ | PROT_WRITE | PROT_EXEC);

	setup_hook(hook, fnptr, jump);

	mprotect((void*) area, bytes, PROT_READ | PROT_EXEC);
};

static void xtrace_setup_misc_hooks(void) {
	setup_hook_with_perms((hook*)&_xtrace_thread_exit, (void*)xtrace_thread_exit_hook, true);
	setup_hook_with_perms((hook*)&_xtrace_execve_inject, (void*)xtrace_execve_inject_hook, true);
	setup_hook_with_perms((hook*)&_xtrace_postfork_child, (void*)xtrace_postfork_child_hook, true);
};

void xtrace_set_gray_color(xtrace::String* log)
{
	if (xtrace_no_color)
		return;

	log->append("\033[37m");
}

void xtrace_reset_color(xtrace::String* log)
{
	if (xtrace_no_color)
		return;

	log->append("\033[0m");
}

void xtrace_start_line(xtrace::String* log, int indent)
{
	xtrace_set_gray_color(log);

	log->append_format("[%d]", sys_thread_selfid());
        for (int i = 0; i < indent + 1; i++)
		log->append(" ");

	xtrace_reset_color(log);
}

static void print_call(xtrace::String* log, const struct calldef* defs, const char* type, int nr, int indent, int gray_name)
{
	xtrace_start_line(log, indent);

	if (gray_name)
		xtrace_set_gray_color(log);

	if (defs[nr].name != NULL)
		log->append_format("%s", defs[nr].name);
	else
		log->append_format("%s %d", type, nr);

	// Leaves gray color on!
}


struct nested_call_struct {
	// We're inside this many calls. In other words, we have printed this many
	// call entries without matching exits.
	int current_level;
	// What that value was the last time. if we've just handled an entry or an
	// exit, this will be greater/less than current_level.
	int previous_level;
	// Call numbers, indexed by current level.
	int nrs[64];
};

DEFINE_XTRACE_TLS_VAR(struct nested_call_struct, nested_call, (struct nested_call_struct) {0}, NULL);

void handle_generic_entry(xtrace::String* log, const struct calldef* defs, const char* type, int nr, void* args[])
{
	if (xtrace_ignore)
		return;

	if (get_ptr_nested_call()->previous_level < get_ptr_nested_call()->current_level && !xtrace_split_entry_and_exit)
	{
		// We are after an earlier entry without an exit.
		xtrace_log("%s\n", log->c_str());
		log->clear();
	}

	int indent = 4 * get_ptr_nested_call()->current_level;
	get_ptr_nested_call()->nrs[get_ptr_nested_call()->current_level] = nr;

	print_call(log, defs, type, nr, indent, 0);

	if (defs[nr].name != NULL && defs[nr].print_args != NULL)
	{
		log->append("(");
		defs[nr].print_args(log, nr, args);
		log->append(")");
	}
	else
		log->append("(...)");

	if (xtrace_split_entry_and_exit) {
		xtrace_log("%s\n", log->c_str());
		log->clear();
	}

	get_ptr_nested_call()->previous_level = get_ptr_nested_call()->current_level++;
}

void handle_generic_exit(xtrace::String* log, const struct calldef* defs, const char* type, uintptr_t retval, int force_split)
{
	if (xtrace_ignore)
		return;

	if (get_ptr_nested_call()->previous_level > get_ptr_nested_call()->current_level)
	{
		// We are after an exit, so our call has been split up.
		force_split = 1;
	}
	get_ptr_nested_call()->previous_level = get_ptr_nested_call()->current_level--;
	int nr = get_ptr_nested_call()->nrs[get_ptr_nested_call()->current_level];

	if (xtrace_split_entry_and_exit || force_split)
	{
		int indent = 4 * get_ptr_nested_call()->current_level;
		print_call(log, defs, type, nr, indent, 1);
		log->append("()");
	}

	xtrace_set_gray_color(log);
	log->append(" -> ");
	xtrace_reset_color(log);

	if (defs[nr].name != NULL && defs[nr].print_retval != NULL)
		defs[nr].print_retval(log, nr, retval);
	else
		log->append_format("0x%lx", retval);

	xtrace_log("%s\n", log->c_str());
	log->clear();
}

extern "C"
void xtrace_log(const char* format, ...) {
	va_list args;
	va_start(args, format);
	xtrace_log_v(format, args);
	va_end(args);
};

// TODO: we should add guarded FD support so that we can make FDs like these logfile descriptors guarded.
//       it would also be very useful to guard the special LKM descriptor.

static void xtrace_common_logfile_init(void) {
	xtrace_common_logfile = _open_for_xtrace(xtrace_logfile_base, O_WRONLY | O_APPEND | O_CLOEXEC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
};

static void ensure_logfile(void) {
	bool created = false;
	int fd = -1;

	if (!xtrace_use_logfile) {
		xtrace_abort("xtrace: tried to use logfile when not enabled");
	}

	if (get_xtrace_per_thread_logfile() != -1) {
		return;
	}

	if (xtrace_use_per_thread_logfile) {
		char filename[sizeof(xtrace_logfile_base)];
		char append[32] = {0};

		strlcpy(filename, xtrace_logfile_base, PATH_MAX);

		__simple_snprintf(append, sizeof(append), ".%d", sys_thread_selfid());
		strlcat(filename, append, PATH_MAX);

		fd = _open_for_xtrace(filename, O_WRONLY | O_APPEND | O_CLOEXEC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	} else {
		xtrace_once(&xtrace_common_logfile_once, xtrace_common_logfile_init);
		fd = xtrace_common_logfile;
	}

	if (fd < 0) {
		xtrace_abort("xtrace: failed to open logfile");
	}

	set_xtrace_per_thread_logfile(fd);
};

extern "C"
void xtrace_log_v(const char* format, va_list args) {
	if (xtrace_kprintf) {
		char real_format[512] = "xtrace: ";
		strlcpy(&real_format[0] + (sizeof("xtrace: ") - 1), format, sizeof(real_format) - (sizeof("xtrace: ") - 1));
		__simple_vkprintf(real_format, args);
	} else if (xtrace_use_logfile) {
		char output[512];
		ensure_logfile();
		__simple_vsnprintf(output, sizeof(output), format, args);
		__write_for_xtrace(get_xtrace_per_thread_logfile(), output, __simple_strlen(output));
	} else {
		__simple_vprintf(format, args);
	}
};

extern "C"
void xtrace_error(const char* format, ...) {
	va_list args;
	va_start(args, format);
	xtrace_error_v(format, args);
	va_end(args);
};

extern "C"
void xtrace_error_v(const char* format, va_list args) {
	if (xtrace_kprintf) {
		char real_format[512] = "xtrace: ";
		strlcpy(real_format + (sizeof("xtrace: ") - 1), format, sizeof(real_format) - (sizeof("xtrace: ") - 1));
		__simple_vkprintf(real_format, args);
	} else if (xtrace_use_logfile) {
		char output[512];
		ensure_logfile();
		__simple_vsnprintf(output, sizeof(output), format, args);
		__write_for_xtrace(get_xtrace_per_thread_logfile(), output, __simple_strlen(output));
	} else {
		__simple_vfprintf(STDERR_FILENO, format, args);
	}
};

extern "C"
void xtrace_abort(const char* message) {
	_abort_with_payload_for_xtrace(0, 0, NULL, 0, message, 0);
	__builtin_unreachable();
};

static void xtrace_thread_exit_hook(void) {
	xtrace_tls_thread_cleanup();
};

static size_t envp_count(const char** envp) {
	size_t count = 0;
	for (const char** ptr = envp; *ptr != NULL; ++ptr) {
		++count;
	}
	return count;
};

static const char** envp_find(const char** envp, const char* key) {
	size_t key_length = strlen(key);

	for (const char** ptr = envp; *ptr != NULL; ++ptr) {
		const char* entry_key = *ptr;
		const char* entry_key_end = strchr(entry_key, '=');
		size_t entry_key_length = entry_key_end - entry_key;

		if (entry_key_length != key_length) {
			continue;
		}

		if (strncmp(key, entry_key, key_length) != 0) {
			continue;
		}

		return ptr;
	}

	return NULL;
};

static const char* envp_make_entry(const char* key, const char* value) {
	size_t key_length = strlen(key);
	size_t value_length = strlen(value);
	char* entry = (char*)xtrace_malloc(key_length + value_length + 2);
	memcpy(entry, key, key_length);
	entry[key_length] = '=';
	memcpy(&entry[key_length + 1], value, value_length);
	entry[key_length + value_length + 2] = '\0';
	return entry;
};

static void envp_set(const char*** envp_ptr, const char* key, const char* value, bool* allocated) {
	const char** envp = *envp_ptr;

	if (!envp) {
		*envp_ptr = envp = (const char**)xtrace_malloc(sizeof(const char*) * 2);
		envp[0] = envp_make_entry(key, value);
		envp[1] = NULL;
		*allocated = true;
	} else {
		const char** entry_ptr = envp_find(envp, key);

		if (entry_ptr) {
			*entry_ptr = envp_make_entry(key, value);
		} else {
			size_t count = envp_count(envp);
			const char** new_envp = (const char**)xtrace_malloc(sizeof(const char*) * (count + 2));

			memcpy(new_envp, envp, sizeof(const char*) * count);

			if (*allocated) {
				xtrace_free(envp);
			}

			new_envp[count] = envp_make_entry(key, value);
			new_envp[count + 1] = NULL;
			*allocated = true;
			*envp_ptr = new_envp;
		}
	}
};

static const char* envp_get(const char** envp, const char* key) {
	const char** entry = envp_find(envp, key);

	if (!entry) {
		return NULL;
	}

	return strchr(*entry, '=') + 1;
};

#define LIBRARY_PATH "/usr/lib/darling/libxtrace.dylib"
#define LIBRARY_PATH_LENGTH (sizeof(LIBRARY_PATH) - 1)

static void xtrace_execve_inject_hook(const char*** envp_ptr) {
	bool allocated = false;

	envp_set(envp_ptr, "XTRACE_SPLIT_ENTRY_AND_EXIT", xtrace_split_entry_and_exit   ? "1" : "0", &allocated);
	envp_set(envp_ptr, "XTRACE_NO_COLOR",             xtrace_no_color               ? "1" : "0", &allocated);
	envp_set(envp_ptr, "XTRACE_KPRINTF",              xtrace_kprintf                ? "1" : "0", &allocated);
	envp_set(envp_ptr, "XTRACE_LOG_FILE_PER_THREAD",  xtrace_use_per_thread_logfile ? "1" : "0", &allocated);
	envp_set(envp_ptr, "XTRACE_LOG_FILE",             xtrace_use_logfile            ? xtrace_logfile_base : "", &allocated);

	const char* insert_libraries = envp_get(*envp_ptr, "DYLD_INSERT_LIBRARIES");
	size_t insert_libraries_length = insert_libraries ? strlen(insert_libraries) : 0;
	char* new_value = (char*)xtrace_malloc(insert_libraries_length + (insert_libraries_length == 0 ? 0 : 1) + LIBRARY_PATH_LENGTH + 1);
	size_t offset = 0;

	if (insert_libraries && insert_libraries_length > 0) {
		memcpy(&new_value[offset], insert_libraries, insert_libraries_length);
		offset += insert_libraries_length;

		new_value[offset] = ':';
		++offset;
	}

	memcpy(&new_value[offset], LIBRARY_PATH, LIBRARY_PATH_LENGTH);
	offset += LIBRARY_PATH_LENGTH;

	new_value[offset] = '\0';

	envp_set(envp_ptr, "DYLD_INSERT_LIBRARIES", new_value, &allocated);
};

static void xtrace_postfork_child_hook(void) {
	// TODO: cleanup TLS

	// reset the per-thread logfile (if necessary)
	if (xtrace_use_per_thread_logfile) {
		int fd = get_xtrace_per_thread_logfile();
		if (fd >= 0) {
			_close_for_xtrace(fd);
		}
		set_xtrace_per_thread_logfile(-1);
	}
};
