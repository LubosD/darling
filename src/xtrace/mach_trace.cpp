#include <darling/emulation/syscall/common/simple.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mach/message.h>
#include <mach/mach_time.h>
#include <mach/mig_errors.h>
#include <servers/bootstrap.h>
#include <pthread.h>


#include "xtracelib.h"
#include "mach_trace.h"
#include "mig_trace.h"
#include "tls.h"
#include "string.h"

DEFINE_XTRACE_TLS_VAR(int, mach_call_nr, -1, NULL);
DEFINE_XTRACE_TLS_VAR(void*, argument_ptr, NULL, NULL);
DEFINE_XTRACE_TLS_VAR(mach_port_name_t, request_port, MACH_PORT_NULL, NULL);

static void print_kern_return(xtrace::String* log, int nr, uintptr_t rv);
static void print_port_return(xtrace::String* log, int nr, uintptr_t rv);
static void print_int_return(xtrace::String* log, int nr, uintptr_t rv);
static void print_empty(xtrace::String* log, int nr, void* args[]);
static void print_port_ptr_return(xtrace::String* log, int nr, uintptr_t rv);

static void print_mach_msg_args(xtrace::String* log, int nr, void* args[]);
static void print_mach_port_insert_right_args(xtrace::String* log, int nr, void* args[]);

static void print_mach_port_member_args(xtrace::String* log, int nr, void* args[]);

static void print_mach_timebase_info_args(xtrace::String* log, int nr, void* args[]);
static void print_mach_timebase_info_res(xtrace::String* log, int nr, uintptr_t rv);

static void print_mach_port_allocate_args(xtrace::String* log, int nr, void* args[]);
static void print_task_for_pid_args(xtrace::String* log, int nr, void* args[]);

static void print_pid_for_task_args(xtrace::String* log, int nr, void* args[]);
static void print_pid_for_task_res(xtrace::String* log, int nr, uintptr_t rv);

static void print_mach_msg_entry(xtrace::String* log, void* args[]);
static void print_mach_msg_exit(xtrace::String* log);

static const struct calldef mach_defs[128] = {
	[10] = { "_kernelrpc_mach_vm_allocate_trap", NULL, print_kern_return },
	[12] = { "_kernelrpc_mach_vm_deallocate_trap", NULL, print_kern_return },
	[14] = { "_kernelrpc_mach_vm_protect_trap", NULL, print_kern_return },
	[15] = { "_kernelrpc_mach_vm_map_trap", NULL, print_kern_return },
	[16] = { "_kernelrpc_mach_port_allocate_trap", print_mach_port_allocate_args, print_port_ptr_return },
	[17] = { "_kernelrpc_mach_port_destroy_trap", NULL, print_kern_return },
	[18] = { "_kernelrpc_mach_port_deallocate_trap", [](xtrace::String* log, int nr, void* args[]) { log->append_format("task %u, port name %u", (unsigned int) (unsigned long) args[0], (unsigned int) (unsigned long) args[1]); }, print_kern_return },
	[19] = { "_kernelrpc_mach_port_mod_refs_trap", NULL, print_kern_return },
	[20] = { "_kernelrpc_mach_port_move_member_trap", print_mach_port_member_args, print_kern_return },
	[21] = { "_kernelrpc_mach_port_insert_right_trap", print_mach_port_insert_right_args, print_kern_return },
	[22] = { "_kernelrpc_mach_port_insert_member_trap", print_mach_port_member_args, print_kern_return },
	[23] = { "_kernelrpc_mach_port_extract_member_trap", print_mach_port_member_args, print_kern_return },
	[24] = { "_kernelrpc_mach_port_construct_trap", NULL, print_kern_return },
	[25] = { "_kernelrpc_mach_port_destruct_trap", NULL, print_kern_return },
	[26] = { "mach_reply_port", print_empty, print_port_return },
	[27] = { "thread_self_trap", print_empty, print_port_return },
	[28] = { "task_self_trap", print_empty, print_port_return },
	[29] = { "host_self_trap", print_empty, print_port_return },
	[31] = { "mach_msg_trap", print_mach_msg_args, print_kern_return },
	[32] = { "mach_msg_overwrite_trap", print_mach_msg_args, print_kern_return },
	[33] = { "semaphore_signal_trap", NULL, print_kern_return },
	[34] = { "semaphore_signal_all_trap", NULL, print_kern_return },
	[35] = { "semaphore_signal_thread_trap", NULL, print_kern_return },
	[36] = { "semaphore_wait_trap", NULL, print_kern_return },
	[37] = { "semaphore_wait_signal_trap", NULL, print_kern_return },
	[38] = { "semaphore_timedwait_trap", NULL, print_kern_return },
	[39] = { "semaphore_timedwait_signal_trap", NULL, print_kern_return },
	[41] = { "_kernelrpc_mach_port_guard_trap", NULL, print_kern_return },
	[42] = { "_kernelrpc_mach_port_unguard_trap", NULL, print_kern_return },
	[43] = { "mach_generate_activity_id", NULL, print_kern_return },
	[44] = { "task_name_for_pid", print_task_for_pid_args, print_port_ptr_return },
	[45] = { "task_for_pid", print_task_for_pid_args, print_port_ptr_return },
	[46] = { "pid_for_task", print_pid_for_task_args, print_pid_for_task_res },
	[48] = { "macx_swapon", NULL, print_kern_return },
	[49] = { "macx_swapoff", NULL, print_kern_return },
	[51] = { "macx_triggers", NULL, print_kern_return },
	[52] = { "macx_backing_store_suspend", NULL, print_kern_return },
	[53] = { "macx_backing_store_recovery", NULL, print_kern_return },
	[59] = { "swtch_pri", NULL, print_kern_return },
	[60] = { "swtch", NULL, print_kern_return },
	[61] = { "syscall_thread_switch", NULL, print_kern_return },
	[62] = { "clock_sleep_trap", NULL, print_kern_return },
	[89] = { "mach_timebase_info_trap", print_mach_timebase_info_args, print_mach_timebase_info_res },
	[90] = { "mach_wait_until", NULL, print_kern_return },
	[91] = { "mk_timer_create", print_empty, print_port_return },
	[92] = { "mk_timer_destroy", NULL, print_kern_return },
	[93] = { "mk_timer_arm", NULL, print_kern_return },
	[94] = { "mk_timer_cancel", NULL, print_kern_return },
};

static const char* const kern_return_values[] = {
	"KERN_SUCCESS",
	"KERN_INVALID_ADDRESS",
	"KERN_PROTECTION_FAILURE",
	"KERN_NO_SPACE",
	"KERN_INVALID_ARGUMENT",
	"KERN_FAILURE",
	"KERN_RESOURCE_SHORTAGE",
	"KERN_NOT_RECEIVER",
	"KERN_NO_ACCESS",
	"KERN_MEMORY_FAILURE",
	"KERN_MEMORY_ERROR",
	"KERN_ALREADY_IN_SET",
	"KERN_NOT_IN_SET",
	"KERN_NAME_EXISTS",
	"KERN_ABORTED",
	"KERN_INVALID_NAME",
	"KERN_INVALID_TASK",
	"KERN_INVALID_RIGHT",
	"KERN_INVALID_VALUE",
	"KERN_UREFS_OVERFLOW",
	"KERN_INVALID_CAPABILITY",
	"KERN_RIGHT_EXISTS",
	"KERN_INVALID_HOST",
	"KERN_MEMORY_PRESENT",
	"KERN_MEMORY_DATA_MOVED",
	"KERN_MEMORY_RESTART_COPY",
	"KERN_INVALID_PROCESSOR_SET",
	"KERN_POLICY_LIMIT",
	"KERN_INVALID_POLICY",
	"KERN_INVALID_OBJECT",
	"KERN_ALREADY_WAITING",
	"KERN_DEFAULT_SET",
	"KERN_EXCEPTION_PROTECTED",
	"KERN_INVALID_LEDGER",
	"KERN_INVALID_MEMORY_CONTROL",
	"KERN_INVALID_SECURITY",
	"KERN_NOT_DEPRESSED",
	"KERN_TERMINATED",
	"KERN_LOCK_SET_DESTROYED",
	"KERN_LOCK_UNSTABLE",
	"KERN_LOCK_OWNED",
	"KERN_LOCK_OWNED_SELF",
	"KERN_SEMAPHORE_DESTROYED",
	"KERN_RPC_SERVER_TERMINATED",
	"KERN_RPC_TERMINATE_ORPHAN",
	"KERN_RPC_CONTINUE_ORPHAN",
	"KERN_NOT_SUPPORTED",
	"KERN_NODE_DOWN",
	"KERN_NOT_WAITING",
	"KERN_OPERATION_TIMED_OUT",
	"KERN_CODESIGN_ERROR",
	"KERN_POLICY_STATIC",
	"KERN_INSUFFICIENT_BUFFER_SIZE",
};

static const char* const mach_send_errors[] = {
	"MACH_SEND_IN_PROGRESS",
	"MACH_SEND_INVALID_DATA",
	"MACH_SEND_INVALID_DEST",
	"MACH_SEND_TIMED_OUT",
	"MACH_SEND_INTERRUPTED",
	"MACH_SEND_MSG_TOO_SMALL",
	"MACH_SEND_INVALID_REPLY",
	"MACH_SEND_INVALID_RIGHT",
	"MACH_SEND_INVALID_NOTIFY",
	"MACH_SEND_INVALID_MEMORY",
	"MACH_SEND_NO_BUFFER",
	"MACH_SEND_TOO_LARGE",
	"MACH_SEND_INVALID_TYPE",
	"MACH_SEND_INVALID_HEADER",
	"MACH_SEND_INVALID_TRAILER"
};

static const char* const mach_rcv_errors[] = {
	"MACH_RCV_IN_PROGRESS",
	"MACH_RCV_INVALID_NAME",
	"MACH_RCV_TIMED_OUT",
	"MACH_RCV_TOO_LARGE",
	"MACH_RCV_INTERRUPTED",
	"MACH_RCV_PORT_CHANGED",
	"MACH_RCV_INVALID_NOTIFY",
	"MACH_RCV_INVALID_DATA",
	"MACH_RCV_PORT_DIED",
	"MACH_RCV_IN_SET",
	"MACH_RCV_HEADER_ERROR",
	"MACH_RCV_BODY_ERROR",
	"MACH_RCV_INVALID_TYPE",
	"MACH_RCV_SCATTER_SMALL",
	"MACH_RCV_INVALID_TRAILER"
};

static const char* const mig_errors[] = {
	"MIG_TYPE_ERROR",
	"MIG_REPLY_MISMATCH",
	"MIG_REMOTE_ERROR",
	"MIG_BAD_ID",
	"MIG_BAD_ARGUMENTS",
	"MIG_NO_REPLY",
	"MIG_EXCEPTION",
	"MIG_ARRAY_TOO_LARGE",
	"MIG_SERVER_DIED",
	"MIG_TRAILER_ERROR"
};

static const char* const bootstrap_errors[] = {
	"BOOTSTRAP_NOT_PRIVILEGED",
	"BOOTSTRAP_NAME_IN_USE",
	"BOOTSTRAP_UNKNOWN_SERVICE",
	"BOOTSTRAP_SERVICE_ACTIVE",
	"BOOTSTRAP_BAD_COUNT",
	"BOOTSTRAP_NO_MEMORY",
	"BOOTSTRAP_NO_CHILDREN"
};

extern "C"
void darling_mach_syscall_entry_print(int nr, void* args[])
{
	xtrace::String log;
#if __i386__
	// get rid of some info in the upper bytes that we don't need
	nr = (int)((unsigned int)nr & 0xffff);
#endif

	set_mach_call_nr(nr);
	handle_generic_entry(&log, mach_defs, "mach", nr, args);
	if (nr == 31 || nr == 32)
		print_mach_msg_entry(&log, args);
	
	if (log.size() > 0) {
		xtrace_log("%s", log.c_str());
		log.clear();
	}
}

extern "C"
void darling_mach_syscall_exit_print(uintptr_t retval)
{
	xtrace::String log;
	int nr = get_mach_call_nr();
	int is_msg = nr == 31 || nr == 32;
	handle_generic_exit(&log, mach_defs, "mach", retval, is_msg);
	if (retval == KERN_SUCCESS && is_msg)
		print_mach_msg_exit(&log);
	set_mach_call_nr(-1);

	if (log.size() > 0) {
		xtrace_log("%s", log.c_str());
		log.clear();
	}
}

void xtrace_print_kern_return(xtrace::String* log, kern_return_t kr)
{
	if (kr >= MACH_RCV_IN_PROGRESS && kr <= MACH_RCV_INVALID_TRAILER)
		log->append_format("%s", mach_rcv_errors[kr - MACH_RCV_IN_PROGRESS]);
	else if (kr >= MACH_SEND_IN_PROGRESS && kr <= MACH_SEND_INVALID_TRAILER)
		log->append_format("%s", mach_send_errors[kr - MACH_SEND_IN_PROGRESS]);
	else if (kr >= KERN_SUCCESS && kr <= KERN_INSUFFICIENT_BUFFER_SIZE)
		log->append_format("%s", kern_return_values[kr]);
	else if (kr >= BOOTSTRAP_NOT_PRIVILEGED && kr <= BOOTSTRAP_NO_CHILDREN)
		log->append_format("%s", bootstrap_errors[kr - BOOTSTRAP_NOT_PRIVILEGED]);
	else if (kr <= MIG_TYPE_ERROR && kr >= MIG_TRAILER_ERROR)
		log->append_format("%s", mig_errors[MIG_TYPE_ERROR - kr]);
	else
		log->append_format("(kern_return_t) %x", kr);
}

static void print_kern_return(xtrace::String* log, int nr, uintptr_t rv)
{
	xtrace_print_kern_return(log, (kern_return_t) rv);
}

static void print_port_return(xtrace::String* log, int nr, uintptr_t rv)
{
	log->append_format("port right %d", (unsigned int) (unsigned long) rv);
}

static void print_int_return(xtrace::String* log, char* buf, int nr, uintptr_t rv)
{
	log->append_format("%d", (int) (long) rv);
}

static void print_empty(xtrace::String* log, int nr, void* args[])
{

}

static void print_port_ptr_return(xtrace::String* log, int nr, uintptr_t rv)
{
	if (rv != KERN_SUCCESS)
	{
		print_kern_return(log, nr, rv);
		set_argument_ptr(NULL);
		return;
	}
	if (get_argument_ptr() == NULL)
	{
		return;
	}
	log->append_format("port right %d", *(mach_port_name_t*)get_argument_ptr());
	set_argument_ptr(NULL);
}


static const char* const port_right_names[] = {
	"MACH_PORT_RIGHT_SEND",
	"MACH_PORT_RIGHT_RECEIVE",
	"MACH_PORT_RIGHT_SEND_ONCE",
	"MACH_PORT_RIGHT_PORT_SET",
	"MACH_PORT_RIGHT_DEAD_NAME",
	"MACH_PORT_RIGHT_NUMBER"
};

static void print_mach_port_allocate_args(xtrace::String* log, int nr, void* args[])
{
	mach_port_name_t target = (mach_port_name_t) (long) args[0];
	mach_port_right_t right = (mach_port_right_t) (long) args[1];
	set_argument_ptr(args[2]);

	const char* right_name;
	if (right > MACH_PORT_RIGHT_NUMBER)
		right_name = "unknown";
	else
		right_name = port_right_names[right];

	log->append_format("task %d, %s", target, right_name);
}

static const char* const port_dispositions[] = {
	"MACH_MSG_TYPE_PORT_NAME",
	"MACH_MSG_TYPE_MOVE_RECEIVE",
	"MACH_MSG_TYPE_MOVE_SEND",
	"MACH_MSG_TYPE_MOVE_SEND_ONCE",
	"MACH_MSG_TYPE_COPY_SEND",
	"MACH_MSG_TYPE_MAKE_SEND",
	"MACH_MSG_TYPE_MAKE_SEND_ONCE",
	"MACH_MSG_TYPE_COPY_RECEIVE",
	"MACH_MSG_TYPE_DISPOSE_RECEIVE",
	"MACH_MSG_TYPE_DISPOSE_SEND",
	"MACH_MSG_TYPE_DISPOSE_SEND_ONCE"
};

static void print_mach_port_insert_right_args(xtrace::String* log, int nr, void* args[])
{
	mach_port_name_t target = (mach_port_name_t) (long) args[0];
	mach_port_name_t name = (mach_port_name_t) (long) args[1];
	mach_port_name_t right = (mach_port_name_t) (long) args[2];
	mach_msg_type_name_t disposition = (mach_msg_type_name_t) (long) args[3];

	const char* disp;
	if (disposition > MACH_MSG_TYPE_DISPOSE_SEND_ONCE || disposition < MACH_MSG_TYPE_PORT_NAME)
		disp = "unknown";
	else
		disp = port_dispositions[disposition - MACH_MSG_TYPE_PORT_NAME];

	log->append_format("task %d, new name %d, port right %d, %s", target, name, right, disp);
}

static void print_mach_port_member_args(xtrace::String* log, int nr, void* args[])
{
	mach_port_name_t target = (mach_port_name_t) (long) args[0];
	mach_port_name_t name = (mach_port_name_t) (long) args[1];
	mach_port_name_t pset = (mach_port_name_t) (long) args[2];

	log->append_format("task %d, port right %d, port set %d", target, name, pset);
}

static void print_mach_timebase_info_args(xtrace::String* log, int nr, void* args[])
{
	set_argument_ptr(args[0]);
	if (get_argument_ptr() == NULL)
		log->append("NULL");
}

static void print_mach_timebase_info_res(xtrace::String* log, int nr, uintptr_t rv)
{
	if (rv != KERN_SUCCESS)
	{
		print_kern_return(log, nr, rv);
		set_argument_ptr(NULL);
		return;
	}
	if (get_argument_ptr() != NULL)
	{
		mach_timebase_info_t timebase = (mach_timebase_info_t)get_argument_ptr();
		log->append_format("numer = %d, denom = %d", timebase->numer, timebase->denom);
	}

	set_argument_ptr(NULL);
}

static void print_task_for_pid_args(xtrace::String* log, int nr, void* args[])
{
	mach_port_name_t target = (mach_port_name_t) (long) args[0];
	int pid = (int) (long) args[1];
	set_argument_ptr(args[2]);

	log->append_format("task %d, pid %d", target, pid);
}

static void print_pid_for_task_args(xtrace::String* log, int nr, void* args[])
{
	mach_port_name_t task = (mach_port_name_t) (long) args[0];
	set_argument_ptr(args[1]);

	log->append_format("task %d", task);
}

static void print_pid_for_task_res(xtrace::String* log, int nr, uintptr_t rv)
{
	if (rv != KERN_SUCCESS)
	{
		print_kern_return(log, nr, rv);
		set_argument_ptr(NULL);
		return;
	}
	if (get_argument_ptr() != NULL)
		log->append_format("pid %d", * (int*)get_argument_ptr());

	set_argument_ptr(NULL);
}

const char* xtrace_msg_type_to_str(mach_msg_type_name_t type_name, int full)
{
	switch (type_name)
	{
		case MACH_MSG_TYPE_MOVE_RECEIVE:
			return full ? "MACH_MSG_TYPE_MOVE_RECEIVE" : "move recv";
		case MACH_MSG_TYPE_MOVE_SEND:
			return full ? "MACH_MSG_TYPE_MOVE_SEND" : "move send";
		case MACH_MSG_TYPE_COPY_SEND:
			return full ? "MACH_MSG_TYPE_COPY_SEND" : "copy send";
		case MACH_MSG_TYPE_MAKE_SEND:
			return full ? "MACH_MSG_TYPE_MAKE_SEND" : "make send";
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
			return full ? "MACH_MSG_TYPE_MOVE_SEND_ONCE" : "move send-once";
		case MACH_MSG_TYPE_MAKE_SEND_ONCE:
			return full ? "MACH_MSG_TYPE_MAKE_SEND_ONCE" : "make send-once";
		default:
			return "unknown";
	}
}

static void print_mach_msg(xtrace::String* log, const mach_msg_header_t* msg, mach_msg_size_t size)
{
	log->append("{");

	mach_msg_bits_t bits = msg->msgh_bits;
	if (MACH_MSGH_BITS_HAS_REMOTE(bits))
		log->append_format("remote = %s %u, ", xtrace_msg_type_to_str(MACH_MSGH_BITS_REMOTE(bits), 0), msg->msgh_remote_port);
	if (MACH_MSGH_BITS_HAS_LOCAL(bits))
		log->append_format("local = %s %u, ", xtrace_msg_type_to_str(MACH_MSGH_BITS_LOCAL(bits), 0), msg->msgh_local_port);
	if (MACH_MSGH_BITS_HAS_VOUCHER(bits))
		log->append_format("voucher = %s %u, ", xtrace_msg_type_to_str(MACH_MSGH_BITS_VOUCHER(bits), 0), msg->msgh_voucher_port);
	if (MACH_MSGH_BITS_IS_COMPLEX(bits))
		log->append("complex, ");

	log->append_format("id = %d}", msg->msgh_id);

	if (!MACH_MSGH_BITS_IS_COMPLEX(bits))
	{
		log->append_format(", %lu bytes of inline data", size - sizeof(mach_msg_header_t));
		xtrace_log("%s\n", log->c_str());
		log->clear();
		return;
	}

	mach_msg_body_t* body = (mach_msg_body_t*) (msg + 1);
	mach_msg_size_t descriptor_count = body->msgh_descriptor_count;
	mach_msg_descriptor_t* ptr = (mach_msg_descriptor_t*) (body + 1);
	for (mach_msg_size_t i = 0; i < descriptor_count; i++)
	{
		mach_msg_descriptor_type_t type = ((mach_msg_type_descriptor_t*) ptr)->type;
		if (type == MACH_MSG_PORT_DESCRIPTOR)
		{
			mach_msg_port_descriptor_t* port = (mach_msg_port_descriptor_t*) ptr;
			log->append_format(", %s %u", xtrace_msg_type_to_str(port->disposition, 0), port->name);
			ptr = (mach_msg_descriptor_t*) (port + 1);
		}
		else if (type == MACH_MSG_OOL_DESCRIPTOR || type == MACH_MSG_OOL_VOLATILE_DESCRIPTOR)
		{
			mach_msg_ool_descriptor_t* ool = (mach_msg_ool_descriptor_t*) ptr;
			log->append_format(", ool [%p; %u]", ool->address, ool->size);
			ptr = (mach_msg_descriptor_t*) (ool + 1);
		}
		else if (type == MACH_MSG_OOL_PORTS_DESCRIPTOR)
		{
			mach_msg_ool_ports_descriptor_t* ool_ports = (mach_msg_ool_ports_descriptor_t*) ptr;
			log->append_format(", ool ports %s [%p; x%u]",
				xtrace_msg_type_to_str(ool_ports->disposition, 0),
				ool_ports->address, ool_ports->count);
			ptr = (mach_msg_descriptor_t*) (ool_ports + 1);
		}
		else
		{
			log->append(", ???");
			ptr++;
		}
	}

	log->append_format(", %lu bytes of inline data", size - ((const char*) ptr - (const char*) msg));
	xtrace_log("%s\n", log->c_str());
	log->clear();
}

static void print_mach_msg_entry(xtrace::String* log, void* args[])
{
	const mach_msg_header_t* message = (const mach_msg_header_t*) args[0];
	mach_msg_option_t options = (mach_msg_option_t) (long) args[1];
	mach_msg_size_t send_size = (mach_msg_size_t) (unsigned long) args[2];

	if (options & MACH_SEND_MSG)
	{
		set_request_port(message->msgh_remote_port);
		xtrace_log("%s\n", log->c_str()); log->clear();
		xtrace_start_line(log, 8);
		print_mach_msg(log, message, send_size);
		xtrace_start_line(log, 8);
		xtrace_print_mig_message(log, message, get_request_port());
		xtrace_log("%s\n", log->c_str()); log->clear();
	}

	if (options & MACH_RCV_MSG)
	{
		switch (get_mach_call_nr())
		{
			case 31:
				// mach_msg_trap
				set_argument_ptr(args[0]);
				break;
			case 32:
				// mach_msg_overwrite_trap
				set_argument_ptr(args[7]);
				if (get_argument_ptr() == NULL)
					set_argument_ptr(args[0]);
				break;
			default:
				log->append("Unexpected mach_call_nr");
				return;
		}
	}
}

static void print_mach_msg_exit(xtrace::String* log)
{
	if (get_argument_ptr() == NULL)
		return;

	const mach_msg_header_t* message = (const mach_msg_header_t*)get_argument_ptr();
	xtrace_start_line(log, 8);
	print_mach_msg(log, message, message->msgh_size);
	xtrace_start_line(log, 8);
	xtrace_print_mig_message(log, message, get_request_port());
	xtrace_log("%s\n", log->c_str()); log->clear();
	set_argument_ptr(NULL);
	set_request_port(MACH_PORT_NULL);
}

static void print_mach_msg_args(xtrace::String* log, int nr, void* args[])
{
	mach_msg_header_t* msg = (mach_msg_header_t*) args[0];
	mach_msg_option_t options = (mach_msg_option_t) (unsigned long) args[1];
	mach_msg_size_t send_size = (mach_msg_size_t) (unsigned long) args[2];
	mach_msg_size_t rcv_size = (mach_msg_size_t) (unsigned long) args[3];
	mach_port_name_t rcv_name = (mach_port_name_t) (unsigned long) args[4];
	mach_msg_timeout_t timeout = (mach_msg_timeout_t) (unsigned long) args[5];
	mach_port_name_t notify = (mach_port_name_t) (unsigned long) args[6];

	log->append_format("%p, ", msg);

	int options_cnt = 0;

#define OPTION(OPT) if (options & OPT) \
	{ \
		if (options_cnt > 0) \
			log->append("|"); \
		log->append(#OPT); \
		options_cnt++; \
	}

	OPTION(MACH_SEND_MSG);
	OPTION(MACH_RCV_MSG);

	OPTION(MACH_RCV_LARGE);
	OPTION(MACH_RCV_LARGE_IDENTITY);

	OPTION(MACH_SEND_TIMEOUT);
	OPTION(MACH_SEND_INTERRUPT);
	OPTION(MACH_SEND_NOTIFY);
	OPTION(MACH_SEND_TRAILER);
	OPTION(MACH_SEND_NOIMPORTANCE);

	OPTION(MACH_RCV_TIMEOUT);
	OPTION(MACH_RCV_NOTIFY);
	OPTION(MACH_RCV_INTERRUPT);
	OPTION(MACH_RCV_VOUCHER);
	OPTION(MACH_RCV_OVERWRITE);

#undef OPTION

	if (options_cnt == 0)
		log->append("MACH_MSG_OPTION_NONE");

	log->append_format(", %d, %d, port %d, %d, port %d", send_size, rcv_size, rcv_name, timeout, notify);
}
