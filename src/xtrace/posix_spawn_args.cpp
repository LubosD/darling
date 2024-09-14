/*
 * This function needs to be in a separate C file rather than in bsd_trace.cpp
 * because `sys/spawn_internal.h` uses some GNU C extensions that C++ doesn't seem to like.
 */

#define PRIVATE 1
#include <sys/spawn_internal.h>
#include <spawn_private.h>

#include <darling/emulation/syscall/common/simple.h>
#include "bsd_trace.h"

#include "xtracelib.h"

static struct {
	unsigned short flag;
	const char* name;
} all_posix_spawn_attrs[] = {
#define POSIX_SPAWN_ATTR_ENTRY(name) { name, #name }
	POSIX_SPAWN_ATTR_ENTRY(POSIX_SPAWN_RESETIDS),
	POSIX_SPAWN_ATTR_ENTRY(POSIX_SPAWN_SETPGROUP),
	POSIX_SPAWN_ATTR_ENTRY(POSIX_SPAWN_SETSIGDEF),
	POSIX_SPAWN_ATTR_ENTRY(POSIX_SPAWN_SETSIGMASK),
	POSIX_SPAWN_ATTR_ENTRY(POSIX_SPAWN_SETEXEC),
	POSIX_SPAWN_ATTR_ENTRY(POSIX_SPAWN_START_SUSPENDED),
	POSIX_SPAWN_ATTR_ENTRY(_POSIX_SPAWN_DISABLE_ASLR),
	POSIX_SPAWN_ATTR_ENTRY(_POSIX_SPAWN_NANO_ALLOCATOR),
	POSIX_SPAWN_ATTR_ENTRY(POSIX_SPAWN_SETSID),
	POSIX_SPAWN_ATTR_ENTRY(_POSIX_SPAWN_ALLOW_DATA_EXEC),
	POSIX_SPAWN_ATTR_ENTRY(POSIX_SPAWN_CLOEXEC_DEFAULT),
	POSIX_SPAWN_ATTR_ENTRY(_POSIX_SPAWN_HIGH_BITS_ASLR),
	{ 0, NULL },
#undef POSIX_SPAWN_ATTR_ENTRY
};

void print_arg_posix_spawn_args(xtrace::String* log, void* arg) {
	const struct _posix_spawn_args_desc* args = (const struct _posix_spawn_args_desc*)(arg);
	bool is_first = true;

	log->append("{ attributes = ");

	if (args && args->attrp) {
		for (size_t i = 0; all_posix_spawn_attrs[i].name != NULL; i++) {
			if (args->attrp->psa_flags & all_posix_spawn_attrs[i].flag) {
				if (is_first) {
					is_first = false;
				} else {
					log->append("|");
				}

				log->append_format("%s", all_posix_spawn_attrs[i].name);
			}
		}
	}

	if (is_first) {
		log->append("0");
	}

	log->append(", file_actions = {");

	if (args && args->file_actions) {
		for (size_t i = 0; i < args->file_actions->psfa_act_count; ++i) {
			const struct _psfa_action* action = &args->file_actions->psfa_act_acts[i];

			if (i != 0) {
				log->append(", ");
			}

			switch (action->psfaa_type) {
				case PSFA_OPEN:
					log->append("open(");
					xtrace_print_string_literal(log, action->psfaa_openargs.psfao_path);
					log->append(", ");
					print_open_flags(log, (void*)(intptr_t)(action->psfaa_openargs.psfao_oflag));
					log->append_format(", 0%o) to %d", action->psfaa_openargs.psfao_mode, action->psfaa_filedes);
					break;

				case PSFA_CLOSE:
					log->append_format("close(%d)", action->psfaa_filedes);
					break;

				case PSFA_DUP2:
					log->append_format("dup2(%d, %d)", action->psfaa_filedes, action->psfaa_dup2args.psfad_newfiledes);
					break;

				case PSFA_INHERIT:
					log->append_format("inherit(%d)", action->psfaa_filedes);
					break;

				case PSFA_FILEPORT_DUP2:
					// NOTE: if we see this in the output, that's an issue;
					//       we don't have this implemented right now
					log->append_format("dup2_fileport(port right %d, %d)", action->psfaa_fileport, action->psfaa_dup2args.psfad_newfiledes);
					break;

				case PSFA_CHDIR:
					log->append("chdir(");
					xtrace_print_string_literal(log, action->psfaa_chdirargs.psfac_path);
					log->append(")");
					break;

				case PSFA_FCHDIR:
					log->append_format("fchdir(%d)", action->psfaa_filedes);
					break;

				default:
					log->append("???");
					break;
			}
		}
	}

	log->append("} }");
};
