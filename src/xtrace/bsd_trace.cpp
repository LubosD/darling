#include <darling/emulation/syscall/common/simple.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <limits.h>

#define PRIVATE 1
#include <spawn_private.h>
#include <sys/event.h>

#include "xtracelib.h"
#include "bsd_trace.h"
#include "tls.h"

static void print_errno(xtrace::String* log, int nr, uintptr_t rv);
static void print_errno_num(xtrace::String* log, int nr, uintptr_t rv);
static void print_errno_ptr(xtrace::String* log, int nr, uintptr_t rv);

static void print_args(xtrace::String* log, int nr, void* args[]);

static void print_kevent_return(xtrace::String* log, int nr, uintptr_t rv);
static void print_kevent_args(xtrace::String* log, int nr, void* args[]);
static void print_kevent64_return(xtrace::String* log, int nr, uintptr_t rv);
static void print_kevent64_args(xtrace::String* log, int nr, void* args[]);
static void print_kevent_qos_return(xtrace::String* log, int nr, uintptr_t rv);
static void print_kevent_qos_args(xtrace::String* log, int nr, void* args[]);

static void print_select_return(xtrace::String* log, int nr, uintptr_t rv);
static void print_select_args(xtrace::String* log, int nr, void* args[]);

static void print_timespec(xtrace::String* log, const struct timespec* timespec);

// awk '/^[0-9]/ { if ($6 !~ "nosys") { split($6, a, "("); print "[" $1 "] = { \"" a[1] "\", print_args, print_errno }," } }'

static const struct calldef bsd_defs[600] = {
	[1] = { "exit", print_args, print_errno_num },
	[2] = { "fork", print_args, print_errno_num },
	[3] = { "read", print_args, print_errno_num },
	[4] = { "write", print_args, print_errno_num },
	[5] = { "open", print_args, print_errno_num },
	[6] = { "close", print_args, print_errno_num },
	[7] = { "wait4", print_args, print_errno_num },
	[9] = { "link", print_args, print_errno_num },
	[10] = { "unlink", print_args, print_errno_num },
	[12] = { "chdir", print_args, print_errno_num },
	[13] = { "fchdir", print_args, print_errno_num },
	[14] = { "mknod", print_args, print_errno_num },
	[15] = { "chmod", print_args, print_errno_num },
	[16] = { "chown", print_args, print_errno_num },
	[18] = { "getfsstat", print_args, print_errno_num },
	[20] = { "getpid", print_args, print_errno_num },
	[23] = { "setuid", print_args, print_errno_num },
	[24] = { "getuid", print_args, print_errno_num },
	[25] = { "geteuid", print_args, print_errno_num },
	[26] = { "ptrace", print_args, print_errno_num },
	[27] = { "recvmsg", print_args, print_errno_num },
	[28] = { "sendmsg", print_args, print_errno_num },
	[29] = { "recvfrom", print_args, print_errno_num },
	[30] = { "accept", print_args, print_errno_num },
	[31] = { "getpeername", print_args, print_errno_num },
	[32] = { "getsockname", print_args, print_errno_num },
	[33] = { "access", print_args, print_errno_num },
	[34] = { "chflags", print_args, print_errno_num },
	[35] = { "fchflags", print_args, print_errno_num },
	[36] = { "sync", print_args, print_errno_num },
	[37] = { "kill", print_args, print_errno_num },
	[39] = { "getppid", print_args, print_errno_num },
	[41] = { "dup", print_args, print_errno_num },
	[42] = { "pipe", print_args, print_errno_num },
	[43] = { "getegid", print_args, print_errno_num },
	[46] = { "sigaction", print_args, print_errno_num },
	[47] = { "getgid", print_args, print_errno_num },
	[48] = { "sigprocmask", print_args, print_errno_num },
	[49] = { "getlogin", print_args, print_errno_num },
	[50] = { "setlogin", print_args, print_errno_num },
	[51] = { "acct", print_args, print_errno_num },
	[52] = { "sigpending", print_args, print_errno_num },
	[53] = { "sigaltstack", print_args, print_errno_num },
	[54] = { "ioctl", print_args, print_errno_num },
	[55] = { "reboot", print_args, print_errno_num },
	[56] = { "revoke", print_args, print_errno_num },
	[57] = { "symlink", print_args, print_errno_num },
	[58] = { "readlink", print_args, print_errno_num },
	[59] = { "execve", print_args, print_errno_num },
	[60] = { "umask", print_args, print_errno_num },
	[61] = { "chroot", print_args, print_errno_num },
	[65] = { "msync", print_args, print_errno_num },
	[66] = { "vfork", print_args, print_errno_num },
	[73] = { "munmap", print_args, print_errno_num },
	[74] = { "mprotect", print_args, print_errno_num },
	[75] = { "madvise", print_args, print_errno_num },
	[78] = { "mincore", print_args, print_errno_num },
	[79] = { "getgroups", print_args, print_errno_num },
	[80] = { "setgroups", print_args, print_errno_num },
	[81] = { "getpgrp", print_args, print_errno_num },
	[82] = { "setpgid", print_args, print_errno_num },
	[83] = { "setitimer", print_args, print_errno_num },
	[85] = { "swapon", print_args, print_errno_num },
	[86] = { "getitimer", print_args, print_errno_num },
	[89] = { "getdtablesize", print_args, print_errno_num },
	[90] = { "dup2", print_args, print_errno_num },
	[92] = { "fcntl", print_args, print_errno_num },
	[93] = { "select", print_select_args, print_select_return },
	[95] = { "fsync", print_args, print_errno_num },
	[96] = { "setpriority", print_args, print_errno_num },
	[97] = { "socket", print_args, print_errno_num },
	[98] = { "connect", print_args, print_errno_num },
	[100] = { "getpriority", print_args, print_errno_num },
	[104] = { "bind", print_args, print_errno_num },
	[105] = { "setsockopt", print_args, print_errno_num },
	[106] = { "listen", print_args, print_errno_num },
	[111] = { "sigsuspend", print_args, print_errno_num },
	[116] = { "gettimeofday", print_args, print_errno_num },
	[117] = { "getrusage", print_args, print_errno_num },
	[118] = { "getsockopt", print_args, print_errno_num },
	[120] = { "readv", print_args, print_errno_num },
	[121] = { "writev", print_args, print_errno_num },
	[122] = { "settimeofday", print_args, print_errno_num },
	[123] = { "fchown", print_args, print_errno_num },
	[124] = { "fchmod", print_args, print_errno_num },
	[126] = { "setreuid", print_args, print_errno_num },
	[127] = { "setregid", print_args, print_errno_num },
	[128] = { "rename", print_args, print_errno_num },
	[131] = { "flock", print_args, print_errno_num },
	[132] = { "mkfifo", print_args, print_errno_num },
	[133] = { "sendto", print_args, print_errno_num },
	[134] = { "shutdown", print_args, print_errno_num },
	[135] = { "socketpair", print_args, print_errno_num },
	[136] = { "mkdir", print_args, print_errno_num },
	[137] = { "rmdir", print_args, print_errno_num },
	[138] = { "utimes", print_args, print_errno_num },
	[139] = { "futimes", print_args, print_errno_num },
	[140] = { "adjtime", print_args, print_errno_num },
	[142] = { "gethostuuid", print_args, print_errno_num },
	[147] = { "setsid", print_args, print_errno_num },
	[151] = { "getpgid", print_args, print_errno_num },
	[152] = { "setprivexec", print_args, print_errno_num },
	[153] = { "pread", print_args, print_errno_num },
	[154] = { "pwrite", print_args, print_errno_num },
	[155] = { "nfssvc", print_args, print_errno_num },
	[157] = { "statfs", print_args, print_errno_num },
	[158] = { "fstatfs", print_args, print_errno_num },
	[159] = { "unmount", print_args, print_errno_num },
	[161] = { "getfh", print_args, print_errno_num },
	[165] = { "quotactl", print_args, print_errno_num },
	[167] = { "mount", print_args, print_errno_num },
	[169] = { "csops", print_args, print_errno_num },
	[170] = { "csops_audittoken", print_args, print_errno_num },
	[173] = { "waitid", print_args, print_errno_num },
	[177] = { "kdebug_typefilter", print_args, print_errno_num },
	[178] = { "kdebug_trace_string", print_args, print_errno_num },
	[179] = { "kdebug_trace64", print_args, print_errno_num },
	[180] = { "kdebug_trace", print_args, print_errno_num },
	[181] = { "setgid", print_args, print_errno_num },
	[182] = { "setegid", print_args, print_errno_num },
	[183] = { "seteuid", print_args, print_errno_num },
	[184] = { "sigreturn", print_args, print_errno_num },
	[187] = { "fdatasync", print_args, print_errno_num },
	[188] = { "stat", print_args, print_errno_num },
	[189] = { "fstat", print_args, print_errno_num },
	[190] = { "lstat", print_args, print_errno_num },
	[191] = { "pathconf", print_args, print_errno_num },
	[192] = { "fpathconf", print_args, print_errno_num },
	[194] = { "getrlimit", print_args, print_errno_num },
	[195] = { "setrlimit", print_args, print_errno_num },
	[196] = { "getdirentries", print_args, print_errno_num },
	[197] = { "mmap", print_args, print_errno_ptr },
	[199] = { "lseek", print_args, print_errno_num },
	[200] = { "truncate", print_args, print_errno_num },
	[201] = { "ftruncate", print_args, print_errno_num },
	[202] = { "sysctl", print_args, print_errno_num },
	[203] = { "mlock", print_args, print_errno_num },
	[204] = { "munlock", print_args, print_errno_num },
	[205] = { "undelete", print_args, print_errno_num },
	[216] = { "open_dprotected_np", print_args, print_errno_num },
	[220] = { "getattrlist", print_args, print_errno_num },
	[221] = { "setattrlist", print_args, print_errno_num },
	[222] = { "getdirentriesattr", print_args, print_errno_num },
	[223] = { "exchangedata", print_args, print_errno_num },
	[225] = { "searchfs", print_args, print_errno_num },
	[226] = { "delete", print_args, print_errno_num },
	[227] = { "copyfile", print_args, print_errno_num },
	[228] = { "fgetattrlist", print_args, print_errno_num },
	[229] = { "fsetattrlist", print_args, print_errno_num },
	[230] = { "poll", print_args, print_errno_num },
	[231] = { "watchevent", print_args, print_errno_num },
	[232] = { "waitevent", print_args, print_errno_num },
	[233] = { "modwatch", print_args, print_errno_num },
	[234] = { "getxattr", print_args, print_errno_num },
	[235] = { "fgetxattr", print_args, print_errno_num },
	[236] = { "setxattr", print_args, print_errno_num },
	[237] = { "fsetxattr", print_args, print_errno_num },
	[238] = { "removexattr", print_args, print_errno_num },
	[239] = { "fremovexattr", print_args, print_errno_num },
	[240] = { "listxattr", print_args, print_errno_num },
	[241] = { "flistxattr", print_args, print_errno_num },
	[242] = { "fsctl", print_args, print_errno_num },
	[243] = { "initgroups", print_args, print_errno_num },
	[244] = { "posix_spawn", print_args, print_errno_num },
	[245] = { "ffsctl", print_args, print_errno_num },
	[247] = { "nfsclnt", print_args, print_errno_num },
	[248] = { "fhopen", print_args, print_errno_num },
	[250] = { "minherit", print_args, print_errno_num },
	[251] = { "semsys", print_args, print_errno_num },
	[252] = { "msgsys", print_args, print_errno_num },
	[253] = { "shmsys", print_args, print_errno_num },
	[254] = { "semctl", print_args, print_errno_num },
	[255] = { "semget", print_args, print_errno_num },
	[256] = { "semop", print_args, print_errno_num },
	[258] = { "msgctl", print_args, print_errno_num },
	[259] = { "msgget", print_args, print_errno_num },
	[260] = { "msgsnd", print_args, print_errno_num },
	[261] = { "msgrcv", print_args, print_errno_num },
	[262] = { "shmat", print_args, print_errno_num },
	[263] = { "shmctl", print_args, print_errno_num },
	[264] = { "shmdt", print_args, print_errno_num },
	[265] = { "shmget", print_args, print_errno_num },
	[266] = { "shm_open", print_args, print_errno_num },
	[267] = { "shm_unlink", print_args, print_errno_num },
	[268] = { "sem_open", print_args, print_errno_num },
	[269] = { "sem_close", print_args, print_errno_num },
	[270] = { "sem_unlink", print_args, print_errno_num },
	[271] = { "sem_wait", print_args, print_errno_num },
	[272] = { "sem_trywait", print_args, print_errno_num },
	[273] = { "sem_post", print_args, print_errno_num },
	[274] = { "sysctlbyname", print_args, print_errno_num },
	[277] = { "open_extended", print_args, print_errno_num },
	[278] = { "umask_extended", print_args, print_errno_num },
	[279] = { "stat_extended", print_args, print_errno_num },
	[280] = { "lstat_extended", print_args, print_errno_num },
	[281] = { "fstat_extended", print_args, print_errno_num },
	[282] = { "chmod_extended", print_args, print_errno_num },
	[283] = { "fchmod_extended", print_args, print_errno_num },
	[284] = { "access_extended", print_args, print_errno_num },
	[285] = { "settid", print_args, print_errno_num },
	[286] = { "gettid", print_args, print_errno_num },
	[287] = { "setsgroups", print_args, print_errno_num },
	[288] = { "getsgroups", print_args, print_errno_num },
	[289] = { "setwgroups", print_args, print_errno_num },
	[290] = { "getwgroups", print_args, print_errno_num },
	[291] = { "mkfifo_extended", print_args, print_errno_num },
	[292] = { "mkdir_extended", print_args, print_errno_num },
	[293] = { "identitysvc", print_args, print_errno_num },
	[294] = { "shared_region_check_np", print_args, print_errno_num },
	[296] = { "vm_pressure_monitor", print_args, print_errno_num },
	[297] = { "psynch_rw_longrdlock", print_args, print_errno_num },
	[298] = { "psynch_rw_yieldwrlock", print_args, print_errno_num },
	[299] = { "psynch_rw_downgrade", print_args, print_errno_num },
	[300] = { "psynch_rw_upgrade", print_args, print_errno_num },
	[301] = { "psynch_mutexwait", print_args, print_errno_num },
	[302] = { "psynch_mutexdrop", print_args, print_errno_num },
	[303] = { "psynch_cvbroad", print_args, print_errno_num },
	[304] = { "psynch_cvsignal", print_args, print_errno_num },
	[305] = { "psynch_cvwait", print_args, print_errno_num },
	[306] = { "psynch_rw_rdlock", print_args, print_errno_num },
	[307] = { "psynch_rw_wrlock", print_args, print_errno_num },
	[308] = { "psynch_rw_unlock", print_args, print_errno_num },
	[309] = { "psynch_rw_unlock2", print_args, print_errno_num },
	[310] = { "getsid", print_args, print_errno_num },
	[311] = { "settid_with_pid", print_args, print_errno_num },
	[312] = { "psynch_cvclrprepost", print_args, print_errno_num },
	[313] = { "aio_fsync", print_args, print_errno_num },
	[314] = { "aio_return", print_args, print_errno_num },
	[315] = { "aio_suspend", print_args, print_errno_num },
	[316] = { "aio_cancel", print_args, print_errno_num },
	[317] = { "aio_error", print_args, print_errno_num },
	[318] = { "aio_read", print_args, print_errno_num },
	[319] = { "aio_write", print_args, print_errno_num },
	[320] = { "lio_listio", print_args, print_errno_num },
	[322] = { "iopolicysys", print_args, print_errno_num },
	[323] = { "process_policy", print_args, print_errno_num },
	[324] = { "mlockall", print_args, print_errno_num },
	[325] = { "munlockall", print_args, print_errno_num },
	[327] = { "issetugid", print_args, print_errno_num },
	[328] = { "__pthread_kill", print_args, print_errno_num },
	[329] = { "__pthread_sigmask", print_args, print_errno_num },
	[330] = { "__sigwait", print_args, print_errno_num },
	[331] = { "__disable_threadsignal", print_args, print_errno_num },
	[332] = { "__pthread_markcancel", print_args, print_errno_num },
	[333] = { "__pthread_canceled", print_args, print_errno_num },
	[334] = { "__semwait_signal", print_args, print_errno_num },
	[336] = { "proc_info", print_args, print_errno_num },
	[337] = { "sendfile", print_args, print_errno_num },
	[338] = { "stat64", print_args, print_errno_num },
	[339] = { "fstat64", print_args, print_errno_num },
	[340] = { "lstat64", print_args, print_errno_num },
	[341] = { "stat64_extended", print_args, print_errno_num },
	[342] = { "lstat64_extended", print_args, print_errno_num },
	[343] = { "fstat64_extended", print_args, print_errno_num },
	[344] = { "getdirentries64", print_args, print_errno_num },
	[345] = { "statfs64", print_args, print_errno_num },
	[346] = { "fstatfs64", print_args, print_errno_num },
	[347] = { "getfsstat64", print_args, print_errno_num },
	[348] = { "__pthread_chdir", print_args, print_errno_num },
	[349] = { "__pthread_fchdir", print_args, print_errno_num },
	[350] = { "audit", print_args, print_errno_num },
	[351] = { "auditon", print_args, print_errno_num },
	[353] = { "getauid", print_args, print_errno_num },
	[354] = { "setauid", print_args, print_errno_num },
	[357] = { "getaudit_addr", print_args, print_errno_num },
	[358] = { "setaudit_addr", print_args, print_errno_num },
	[359] = { "auditctl", print_args, print_errno_num },
	[360] = { "bsdthread_create", print_args, print_errno_num },
	[361] = { "bsdthread_terminate", print_args, print_errno_num },
	[362] = { "kqueue", print_args, print_errno_num },

	// kevent is special
	[363] = { "kevent", print_kevent_args, print_kevent_return },

	[364] = { "lchown", print_args, print_errno_num },
	[366] = { "bsdthread_register", print_args, print_errno_num },
	[367] = { "workq_open", print_args, print_errno_num },
	[368] = { "workq_kernreturn", print_args, print_errno_num },

	// kevent64 is special
	[369] = { "kevent64", print_kevent64_args, print_kevent64_return },

	[370] = { "__old_semwait_signal", print_args, print_errno_num },
	[371] = { "__old_semwait_signal_nocancel", print_args, print_errno_num },
	[372] = { "thread_selfid", print_args, print_errno_num },
	[373] = { "ledger", print_args, print_errno_num },

	// kevent_qos is special
	[374] = { "kevent_qos", print_kevent_qos_args, print_kevent_qos_return },

	[380] = { "__mac_execve", print_args, print_errno_num },
	[381] = { "__mac_syscall", print_args, print_errno_num },
	[382] = { "__mac_get_file", print_args, print_errno_num },
	[383] = { "__mac_set_file", print_args, print_errno_num },
	[384] = { "__mac_get_link", print_args, print_errno_num },
	[385] = { "__mac_set_link", print_args, print_errno_num },
	[386] = { "__mac_get_proc", print_args, print_errno_num },
	[387] = { "__mac_set_proc", print_args, print_errno_num },
	[388] = { "__mac_get_fd", print_args, print_errno_num },
	[389] = { "__mac_set_fd", print_args, print_errno_num },
	[390] = { "__mac_get_pid", print_args, print_errno_num },
	[394] = { "pselect", print_args, print_errno_num },
	[395] = { "pselect_nocancel", print_args, print_errno_num },
	[396] = { "read_nocancel", print_args, print_errno_num },
	[397] = { "write_nocancel", print_args, print_errno_num },
	[398] = { "open_nocancel", print_args, print_errno_num },
	[399] = { "close_nocancel", print_args, print_errno_num },
	[400] = { "wait4_nocancel", print_args, print_errno_num },
	[401] = { "recvmsg_nocancel", print_args, print_errno_num },
	[402] = { "sendmsg_nocancel", print_args, print_errno_num },
	[403] = { "recvfrom_nocancel", print_args, print_errno_num },
	[404] = { "accept_nocancel", print_args, print_errno_num },
	[405] = { "msync_nocancel", print_args, print_errno_num },
	[406] = { "fcntl_nocancel", print_args, print_errno_num },
	[407] = { "select_nocancel", print_args, print_errno_num },
	[408] = { "fsync_nocancel", print_args, print_errno_num },
	[409] = { "connect_nocancel", print_args, print_errno_num },
	[410] = { "sigsuspend_nocancel", print_args, print_errno_num },
	[411] = { "readv_nocancel", print_args, print_errno_num },
	[412] = { "writev_nocancel", print_args, print_errno_num },
	[413] = { "sendto_nocancel", print_args, print_errno_num },
	[414] = { "pread_nocancel", print_args, print_errno_num },
	[415] = { "pwrite_nocancel", print_args, print_errno_num },
	[416] = { "waitid_nocancel", print_args, print_errno_num },
	[417] = { "poll_nocancel", print_args, print_errno_num },
	[418] = { "msgsnd_nocancel", print_args, print_errno_num },
	[419] = { "msgrcv_nocancel", print_args, print_errno_num },
	[420] = { "sem_wait_nocancel", print_args, print_errno_num },
	[421] = { "aio_suspend_nocancel", print_args, print_errno_num },
	[422] = { "__sigwait_nocancel", print_args, print_errno_num },
	[423] = { "__semwait_signal_nocancel", print_args, print_errno_num },
	[424] = { "__mac_mount", print_args, print_errno_num },
	[425] = { "__mac_get_mount", print_args, print_errno_num },
	[426] = { "__mac_getfsstat", print_args, print_errno_num },
	[427] = { "fsgetpath", print_args, print_errno_num },
	[428] = { "audit_session_self", print_args, print_errno_num },
	[429] = { "audit_session_join", print_args, print_errno_num },
	[430] = { "fileport_makeport", print_args, print_errno_num },
	[431] = { "fileport_makefd", print_args, print_errno_num },
	[432] = { "audit_session_port", print_args, print_errno_num },
	[433] = { "pid_suspend", print_args, print_errno_num },
	[434] = { "pid_resume", print_args, print_errno_num },
	[438] = { "shared_region_map_and_slide_np", print_args, print_errno_num },
	[439] = { "kas_info", print_args, print_errno_num },
	[440] = { "memorystatus_control", print_args, print_errno_num },
	[441] = { "guarded_open_np", print_args, print_errno_num },
	[442] = { "guarded_close_np", print_args, print_errno_num },
	[443] = { "guarded_kqueue_np", print_args, print_errno_num },
	[444] = { "change_fdguard_np", print_args, print_errno_num },
	[445] = { "usrctl", print_args, print_errno_num },
	[446] = { "proc_rlimit_control", print_args, print_errno_num },
	[447] = { "connectx", print_args, print_errno_num },
	[448] = { "disconnectx", print_args, print_errno_num },
	[449] = { "peeloff", print_args, print_errno_num },
	[450] = { "socket_delegate", print_args, print_errno_num },
	[451] = { "telemetry", print_args, print_errno_num },
	[452] = { "proc_uuid_policy", print_args, print_errno_num },
	[453] = { "memorystatus_get_level", print_args, print_errno_num },
	[454] = { "system_override", print_args, print_errno_num },
	[455] = { "vfs_purge", print_args, print_errno_num },
	[456] = { "sfi_ctl", print_args, print_errno_num },
	[457] = { "sfi_pidctl", print_args, print_errno_num },
	[458] = { "coalition", print_args, print_errno_num },
	[459] = { "coalition_info", print_args, print_errno_num },
	[460] = { "necp_match_policy", print_args, print_errno_num },
	[461] = { "getattrlistbulk", print_args, print_errno_num },
	[462] = { "clonefileat", print_args, print_errno_num },
	[463] = { "openat", print_args, print_errno_num },
	[464] = { "openat_nocancel", print_args, print_errno_num },
	[465] = { "renameat", print_args, print_errno_num },
	[466] = { "faccessat", print_args, print_errno_num },
	[467] = { "fchmodat", print_args, print_errno_num },
	[468] = { "fchownat", print_args, print_errno_num },
	[469] = { "fstatat", print_args, print_errno_num },
	[470] = { "fstatat64", print_args, print_errno_num },
	[471] = { "linkat", print_args, print_errno_num },
	[472] = { "unlinkat", print_args, print_errno_num },
	[473] = { "readlinkat", print_args, print_errno_num },
	[474] = { "symlinkat", print_args, print_errno_num },
	[475] = { "mkdirat", print_args, print_errno_num },
	[476] = { "getattrlistat", print_args, print_errno_num },
	[477] = { "proc_trace_log", print_args, print_errno_num },
	[478] = { "bsdthread_ctl", print_args, print_errno_num },
	[479] = { "openbyid_np", print_args, print_errno_num },
	[480] = { "recvmsg_x", print_args, print_errno_num },
	[481] = { "sendmsg_x", print_args, print_errno_num },
	[482] = { "thread_selfusage", print_args, print_errno_num },
	[483] = { "csrctl", print_args, print_errno_num },
	[484] = { "guarded_open_dprotected_np", print_args, print_errno_num },
	[485] = { "guarded_write_np", print_args, print_errno_num },
	[486] = { "guarded_pwrite_np", print_args, print_errno_num },
	[487] = { "guarded_writev_np", print_args, print_errno_num },
	[488] = { "renameatx_np", print_args, print_errno_num },
	[489] = { "mremap_encrypted", print_args, print_errno_num },
	[490] = { "netagent_trigger", print_args, print_errno_num },
	[491] = { "stack_snapshot_with_config", print_args, print_errno_num },
	[492] = { "microstackshot", print_args, print_errno_num },
	[493] = { "grab_pgo_data", print_args, print_errno_num },
	[494] = { "persona", print_args, print_errno_num },
	[499] = { "work_interval_ctl", print_args, print_errno_num },
	[500] = { "getentropy", print_args, print_errno_num },
	[501] = { "necp_open", print_args, print_errno_num },
	[502] = { "necp_client_action", print_args, print_errno_num },
	[515] = { "ulock_wait", print_args, print_errno_num },
	[516] = { "ulock_wake", print_args, print_errno_num },
	[517] = { "fclonefileat", print_args, print_errno_num },
	[518] = { "fs_snapshot", print_args, print_errno_num },
	[520] = { "terminate_with_payload", print_args, print_errno_num },
	[521] = { "abort_with_payload", print_args, print_errno_num },
};

static void print_arg_int(xtrace::String* log, void* arg)
{
	log->append_format("%d", (int) (long) arg);
}

static void print_arg_ptr(xtrace::String* log, void* arg)
{
	if (arg == NULL)
		log->append("NULL");
	else
		log->append_format("%p", arg);
}

void xtrace_print_string_literal(xtrace::String* log, const char* str) {
	if (str == NULL) {
		log->append("NULL");
		return;
	}

	if (!xtrace_no_color)
		log->append("\033[;1m"); // bold

	log->append("\"");

	for (; *str; str++)
	{
		switch (*str)
		{
			case '\\':
				log->append("\\\\");
				break;
			case '\n':
				log->append("\\n");
				break;
			case '\t':
				log->append("\\t");
				break;
			default:
				log->append_format("%c", *str);
				break;
		}
	}

	log->append("\"");

	if (!xtrace_no_color)
		log->append("\033[0m"); // reset
}

static void print_arg_str(xtrace::String* log, void* arg)
{
	const char* str = (const char*) arg;
	xtrace_print_string_literal(log, str);
}

static void print_arg_prot(xtrace::String* log, void* arg)
{
	int cnt = 0;
	int prot = (int)(long)arg;

	if (prot & PROT_READ)
	{
		log->append("PROT_READ");
		cnt++;
	}
	if (prot & PROT_WRITE)
	{
		if (cnt > 0)
			log->append("|");
		log->append("PROT_WRITE");
		cnt++;
	}
	if (prot & PROT_EXEC)
	{
		if (cnt > 0)
			log->append("|");
		log->append("PROT_EXEC");
		cnt++;
	}
	if (cnt == 0)
	{
		log->append("PROT_NONE");
	}
}

static void print_mmap_flags(xtrace::String* log, void* arg)
{
	int cnt = 0;
	int flags = (int) (long) arg;

	static const struct {
		int flag;
		const char* name;
	} all_flags[] = {
		{ MAP_ANON, "MAP_ANON" },
		{ MAP_FIXED, "MAP_FIXED" },
		{ MAP_HASSEMAPHORE, "MAP_HASSEMAPHORE" },
		{ MAP_PRIVATE, "MAP_PRIVATE" },
		{ MAP_SHARED, "MAP_SHARED" },
		{ MAP_NOCACHE, "MAP_NOCACHE" },
		{ 0, NULL }
	};

	for (int i = 0; all_flags[i].name != NULL; i++)
	{
		if (flags & all_flags[i].flag)
		{
			if (cnt > 0)
				log->append("|");
			log->append_format("%s", all_flags[i].name);
			cnt++;
		}
	}

	if (cnt == 0)
	{
		log->append("MAP_FILE");
	}
}

void print_open_flags(xtrace::String* log, void* arg)
{
	int cnt = 0;
	int flags = (int) (long) arg;

	struct {
		int flag;
		const char* name;
	} all_flags[] = {
		{ O_WRONLY, "O_WRONLY" },
		{ O_RDWR, "O_RDWR" },
		{ O_NONBLOCK, "O_NONBLOCK" },
		{ O_APPEND, "O_APPEND" },
		{ O_CREAT, "O_CREAT" },
		{ O_TRUNC, "O_TRUNC" },
		{ O_EXCL, "O_EXCL" },
		{ O_SHLOCK, "O_SHLOCK" },
		{ O_EXLOCK, "O_EXLOCK" },
		{ O_NOFOLLOW, "O_NOFOLLOW" },
		{ O_SYMLINK, "O_SYMLINK" },
		{ O_DIRECTORY, "O_DIRECTORY" },
		{ O_EVTONLY, "O_EVTONLY" },
		{ O_CLOEXEC, "O_CLOEXEC" },
		{ O_NOCTTY, "O_NOCTTY" },
		{ 0, NULL }
	};

	for (int i = 0; all_flags[i].name != NULL; i++)
	{
		if (flags & all_flags[i].flag)
		{
			if (cnt > 0)
				log->append("|");
			log->append_format("%s", all_flags[i].name);
			cnt++;
		}
	}

	if (cnt == 0)
	{
		log->append("O_RDONLY");
	}
}

extern void print_arg_posix_spawn_args(xtrace::String* log, void* arg);

static void print_arg_string_array(xtrace::String* log, void* arg) {
	const char* const* array = (const char* const*)arg;
	bool is_first = true;

	log->append("{");

	if (array) {
		for (const char* const* ptr = array; *ptr != NULL; ++ptr) {
			if (is_first) {
				is_first = false;
			} else {
				log->append(", ");
			}

			xtrace_print_string_literal(log, *ptr);
		}
	}

	log->append("}");
};

// TODO: output more specific information for more calls

static const struct {
	int args_cnt;
	void (*print_arg[8])(xtrace::String* log, void* arg);
} args_info[] = {
	[1] = { 1, { print_arg_int } }, // exit
	[2] = { 0, {  } }, // fork
	[3] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // read
	[4] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // write
	[5] = { 3, { print_arg_str, print_open_flags, print_arg_int } }, // open
	[6] = { 1, { print_arg_int } }, // close
	[7] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr } }, // wait4
	[9] = { 2, { print_arg_str, print_arg_str } }, // link
	[10] = { 1, { print_arg_str } }, // unlink
	[12] = { 1, { print_arg_str } }, // chdir
	[13] = { 1, { print_arg_int } }, // fchdir
	[14] = { 3, { print_arg_str, print_arg_int, print_arg_int } }, // mknod
	[15] = { 2, { print_arg_str, print_arg_int } }, // chmod
	[16] = { 3, { print_arg_str, print_arg_int, print_arg_int } }, // chown
	[18] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // getfsstat
	[20] = { 0, {  } }, // getpid
	[23] = { 1, { print_arg_int } }, // setuid
	[24] = { 0, {  } }, // getuid
	[25] = { 0, {  } }, // geteuid
	[26] = { 4, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // ptrace
	[27] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // recvmsg
	[28] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // sendmsg
	[29] = { 6, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_ptr, print_arg_ptr } }, // recvfrom
	[30] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // accept
	[31] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // getpeername
	[32] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // getsockname
	[33] = { 2, { print_arg_str, print_arg_int } }, // access
	[34] = { 2, { print_arg_str, print_arg_int } }, // chflags
	[35] = { 2, { print_arg_int, print_arg_int } }, // fchflags
	[36] = { 0, {  } }, // sync
	[37] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // kill
	[39] = { 0, {  } }, // getppid
	[41] = { 1, { print_arg_int } }, // dup
	[42] = { 0, {  } }, // pipe
	[43] = { 0, {  } }, // getegid
	[46] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // sigaction
	[47] = { 0, {  } }, // getgid
	[48] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // sigprocmask
	[49] = { 2, { print_arg_ptr, print_arg_int } }, // getlogin
	[50] = { 1, { print_arg_ptr } }, // setlogin
	[51] = { 1, { print_arg_str } }, // acct
	[52] = { 1, { print_arg_ptr } }, // sigpending
	[53] = { 2, { print_arg_ptr, print_arg_ptr } }, // sigaltstack
	[54] = { 3, { print_arg_int, print_arg_int, print_arg_ptr } }, // ioctl
	[55] = { 2, { print_arg_int, print_arg_ptr } }, // reboot
	[56] = { 1, { print_arg_str } }, // revoke
	[57] = { 2, { print_arg_str, print_arg_str } }, // symlink
	[58] = { 3, { print_arg_str, print_arg_ptr, print_arg_int } }, // readlink
	[59] = { 3, { print_arg_str, print_arg_string_array, print_arg_string_array } }, // execve
	[60] = { 1, { print_arg_int } }, // umask
	[61] = { 1, { print_arg_str } }, // chroot
	[65] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // msync
	[66] = { 0, {  } }, // vfork
	[73] = { 2, { print_arg_ptr, print_arg_int } }, // munmap
	[74] = { 3, { print_arg_ptr, print_arg_int, print_arg_prot } }, // mprotect
	[75] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // madvise
	[78] = { 3, { print_arg_ptr, print_arg_int, print_arg_ptr } }, // mincore
	[79] = { 2, { print_arg_int, print_arg_ptr } }, // getgroups
	[80] = { 2, { print_arg_int, print_arg_ptr } }, // setgroups
	[81] = { 0, {  } }, // getpgrp
	[82] = { 2, { print_arg_int, print_arg_int } }, // setpgid
	[83] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // setitimer
	[85] = { 0, {  } }, // swapon
	[86] = { 2, { print_arg_int, print_arg_ptr } }, // getitimer
	[89] = { 0, {  } }, // getdtablesize
	[90] = { 2, { print_arg_int, print_arg_int } }, // dup2
	[92] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // fcntl
	// select is special
	[95] = { 1, { print_arg_int } }, // fsync
	[96] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // setpriority
	[97] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // socket
	[98] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // connect
	[100] = { 2, { print_arg_int, print_arg_int } }, // getpriority
	[104] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // bind
	[105] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // setsockopt
	[106] = { 2, { print_arg_int, print_arg_int } }, // listen
	[111] = { 1, { print_arg_int } }, // sigsuspend
	[116] = { 3, { print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // gettimeofday
	[117] = { 2, { print_arg_int, print_arg_ptr } }, // getrusage
	[118] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_ptr } }, // getsockopt
	[120] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // readv
	[121] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // writev
	[122] = { 2, { print_arg_ptr, print_arg_ptr } }, // settimeofday
	[123] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // fchown
	[124] = { 2, { print_arg_int, print_arg_int } }, // fchmod
	[126] = { 2, { print_arg_int, print_arg_int } }, // setreuid
	[127] = { 2, { print_arg_int, print_arg_int } }, // setregid
	[128] = { 2, { print_arg_str, print_arg_str } }, // rename
	[131] = { 2, { print_arg_int, print_arg_int } }, // flock
	[132] = { 2, { print_arg_str, print_arg_int } }, // mkfifo
	[133] = { 6, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // sendto
	[134] = { 2, { print_arg_int, print_arg_int } }, // shutdown
	[135] = { 4, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // socketpair
	[136] = { 2, { print_arg_str, print_arg_int } }, // mkdir
	[137] = { 1, { print_arg_str } }, // rmdir
	[138] = { 2, { print_arg_str, print_arg_ptr } }, // utimes
	[139] = { 2, { print_arg_int, print_arg_ptr } }, // futimes
	[140] = { 2, { print_arg_ptr, print_arg_ptr } }, // adjtime
	[142] = { 3, { print_arg_ptr, print_arg_ptr, print_arg_int } }, // gethostuuid
	[147] = { 0, {  } }, // setsid
	[151] = { 1, { print_arg_int } }, // getpgid
	[152] = { 1, { print_arg_int } }, // setprivexec
	[153] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // pread
	[154] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // pwrite
	[155] = { 2, { print_arg_int, print_arg_ptr } }, // nfssvc
	[157] = { 2, { print_arg_str, print_arg_ptr } }, // statfs
	[158] = { 2, { print_arg_int, print_arg_ptr } }, // fstatfs
	[159] = { 2, { print_arg_str, print_arg_int } }, // unmount
	[161] = { 2, { print_arg_ptr, print_arg_ptr } }, // getfh
	[165] = { 4, { print_arg_str, print_arg_int, print_arg_int, print_arg_ptr } }, // quotactl
	[167] = { 4, { print_arg_str, print_arg_str, print_arg_int, print_arg_ptr } }, // mount
	[169] = { 4, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // csops
	[170] = { 5, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr } }, // csops_audittoken
	[173] = { 4, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // waitid
	[177] = { 2, { print_arg_ptr, print_arg_ptr } }, // kdebug_typefilter
	[178] = { 3, { print_arg_int, print_arg_int, print_arg_str } }, // kdebug_trace_string
	[179] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // kdebug_trace64
	[180] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // kdebug_trace
	[181] = { 1, { print_arg_int } }, // setgid
	[182] = { 1, { print_arg_int } }, // setegid
	[183] = { 1, { print_arg_int } }, // seteuid
	[184] = { 2, { print_arg_ptr, print_arg_int } }, // sigreturn
	[187] = { 1, { print_arg_int } }, // fdatasync
	[188] = { 2, { print_arg_str, print_arg_ptr } }, // stat
	[189] = { 2, { print_arg_int, print_arg_ptr } }, // fstat
	[190] = { 2, { print_arg_str, print_arg_ptr } }, // lstat
	[191] = { 2, { print_arg_str, print_arg_int } }, // pathconf
	[192] = { 2, { print_arg_int, print_arg_int } }, // fpathconf
	[194] = { 2, { print_arg_int, print_arg_ptr } }, // getrlimit
	[195] = { 2, { print_arg_int, print_arg_ptr } }, // setrlimit
	[196] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr } }, // getdirentries
	[197] = { 6, { print_arg_ptr, print_arg_int, print_arg_prot, print_mmap_flags, print_arg_int, print_arg_int } }, // mmap
	[199] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // lseek
	[200] = { 2, { print_arg_str, print_arg_int } }, // truncate
	[201] = { 2, { print_arg_int, print_arg_int } }, // ftruncate
	[202] = { 6, { print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_int } }, // sysctl
	[203] = { 2, { print_arg_ptr, print_arg_int } }, // mlock
	[204] = { 2, { print_arg_ptr, print_arg_int } }, // munlock
	[205] = { 1, { print_arg_str } }, // undelete
	[216] = { 5, { print_arg_str, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // open_dprotected_np
	[220] = { 5, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // getattrlist
	[221] = { 5, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // setattrlist
	[222] = { 8, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_int } }, // getdirentriesattr
	[223] = { 3, { print_arg_str, print_arg_str, print_arg_int } }, // exchangedata
	[225] = { 6, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int, print_arg_ptr } }, // searchfs
	[226] = { 1, { print_arg_str } }, // delete
	[227] = { 4, { print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // copyfile
	[228] = { 5, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // fgetattrlist
	[229] = { 5, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // fsetattrlist
	[230] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // poll
	[231] = { 2, { print_arg_ptr, print_arg_int } }, // watchevent
	[232] = { 2, { print_arg_ptr, print_arg_ptr } }, // waitevent
	[233] = { 2, { print_arg_ptr, print_arg_int } }, // modwatch
	[234] = { 6, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // getxattr
	[235] = { 6, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // fgetxattr
	[236] = { 6, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // setxattr
	[237] = { 6, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // fsetxattr
	[238] = { 3, { print_arg_str, print_arg_ptr, print_arg_int } }, // removexattr
	[239] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // fremovexattr
	[240] = { 4, { print_arg_str, print_arg_ptr, print_arg_int, print_arg_int } }, // listxattr
	[241] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // flistxattr
	[242] = { 4, { print_arg_str, print_arg_int, print_arg_ptr, print_arg_int } }, // fsctl
	[243] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // initgroups
	[244] = { 5, { print_arg_ptr, print_arg_str, print_arg_posix_spawn_args, print_arg_string_array, print_arg_string_array } }, // posix_spawn
	[245] = { 4, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // ffsctl
	[247] = { 2, { print_arg_int, print_arg_ptr } }, // nfsclnt
	[248] = { 2, { print_arg_ptr, print_arg_int } }, // fhopen
	[250] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // minherit
	[251] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // semsys
	[252] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // msgsys
	[253] = { 4, { print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // shmsys
	[254] = { 4, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // semctl
	[255] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // semget
	[256] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // semop
	[258] = { 3, { print_arg_int, print_arg_int, print_arg_ptr } }, // msgctl
	[259] = { 2, { print_arg_int, print_arg_int } }, // msgget
	[260] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // msgsnd
	[261] = { 5, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // msgrcv
	[262] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // shmat
	[263] = { 3, { print_arg_int, print_arg_int, print_arg_ptr } }, // shmctl
	[264] = { 1, { print_arg_ptr } }, // shmdt
	[265] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // shmget
	[266] = { 3, { print_arg_str, print_arg_int, print_arg_int } }, // shm_open
	[267] = { 1, { print_arg_str } }, // shm_unlink
	[268] = { 4, { print_arg_str, print_arg_int, print_arg_int, print_arg_int } }, // sem_open
	[269] = { 1, { print_arg_ptr } }, // sem_close
	[270] = { 1, { print_arg_str } }, // sem_unlink
	[271] = { 1, { print_arg_ptr } }, // sem_wait
	[272] = { 1, { print_arg_ptr } }, // sem_trywait
	[273] = { 1, { print_arg_ptr } }, // sem_post
	[274] = { 6, { print_arg_str, print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_int } }, // sysctlbyname
	[277] = { 6, { print_arg_str, print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // open_extended
	[278] = { 2, { print_arg_int, print_arg_ptr } }, // umask_extended
	[279] = { 4, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // stat_extended
	[280] = { 4, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // lstat_extended
	[281] = { 4, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // fstat_extended
	[282] = { 5, { print_arg_str, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // chmod_extended
	[283] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // fchmod_extended
	[284] = { 4, { print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int } }, // access_extended
	[285] = { 2, { print_arg_int, print_arg_int } }, // settid
	[286] = { 2, { print_arg_ptr, print_arg_ptr } }, // gettid
	[287] = { 2, { print_arg_int, print_arg_ptr } }, // setsgroups
	[288] = { 2, { print_arg_ptr, print_arg_ptr } }, // getsgroups
	[289] = { 2, { print_arg_int, print_arg_ptr } }, // setwgroups
	[290] = { 2, { print_arg_ptr, print_arg_ptr } }, // getwgroups
	[291] = { 5, { print_arg_str, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // mkfifo_extended
	[292] = { 5, { print_arg_str, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // mkdir_extended
	[293] = { 2, { print_arg_int, print_arg_ptr } }, // identitysvc
	[294] = { 1, { print_arg_ptr } }, // shared_region_check_np
	[296] = { 3, { print_arg_int, print_arg_int, print_arg_ptr } }, // vm_pressure_monitor
	[297] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_rw_longrdlock
	[298] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_rw_yieldwrlock
	[299] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_rw_downgrade
	[300] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_rw_upgrade
	[301] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_mutexwait
	[302] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_mutexdrop
	[303] = { 7, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // psynch_cvbroad
	[304] = { 8, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // psynch_cvsignal
	[305] = { 8, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_cvwait
	[306] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_rw_rdlock
	[307] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_rw_wrlock
	[308] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_rw_unlock
	[309] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_rw_unlock2
	[310] = { 1, { print_arg_int } }, // getsid
	[311] = { 2, { print_arg_int, print_arg_int } }, // settid_with_pid
	[312] = { 7, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // psynch_cvclrprepost
	[313] = { 2, { print_arg_int, print_arg_ptr } }, // aio_fsync
	[314] = { 1, { print_arg_ptr } }, // aio_return
	[315] = { 3, { print_arg_ptr, print_arg_int, print_arg_ptr } }, // aio_suspend
	[316] = { 2, { print_arg_int, print_arg_ptr } }, // aio_cancel
	[317] = { 1, { print_arg_ptr } }, // aio_error
	[318] = { 1, { print_arg_ptr } }, // aio_read
	[319] = { 1, { print_arg_ptr } }, // aio_write
	[320] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr } }, // lio_listio
	[322] = { 2, { print_arg_int, print_arg_ptr } }, // iopolicysys
	[323] = { 7, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // process_policy
	[324] = { 1, { print_arg_int } }, // mlockall
	[325] = { 1, { print_arg_int } }, // munlockall
	[327] = { 0, {  } }, // issetugid
	[328] = { 2, { print_arg_int, print_arg_int } }, // __pthread_kill
	[329] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // __pthread_sigmask
	[330] = { 2, { print_arg_ptr, print_arg_ptr } }, // __sigwait
	[331] = { 1, { print_arg_int } }, // __disable_threadsignal
	[332] = { 1, { print_arg_int } }, // __pthread_markcancel
	[333] = { 1, { print_arg_int } }, // __pthread_canceled
	[334] = { 6, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // __semwait_signal
	[336] = { 6, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // proc_info
	[337] = { 6, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int } }, // sendfile
	[338] = { 2, { print_arg_str, print_arg_ptr } }, // stat64
	[339] = { 2, { print_arg_int, print_arg_ptr } }, // fstat64
	[340] = { 2, { print_arg_str, print_arg_ptr } }, // lstat64
	[341] = { 4, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // stat64_extended
	[342] = { 4, { print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // lstat64_extended
	[343] = { 4, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // fstat64_extended
	[344] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr } }, // getdirentries64
	[345] = { 2, { print_arg_str, print_arg_ptr } }, // statfs64
	[346] = { 2, { print_arg_int, print_arg_ptr } }, // fstatfs64
	[347] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // getfsstat64
	[348] = { 1, { print_arg_str } }, // __pthread_chdir
	[349] = { 1, { print_arg_int } }, // __pthread_fchdir
	[350] = { 2, { print_arg_ptr, print_arg_int } }, // audit
	[351] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // auditon
	[353] = { 1, { print_arg_ptr } }, // getauid
	[354] = { 1, { print_arg_ptr } }, // setauid
	[357] = { 2, { print_arg_ptr, print_arg_int } }, // getaudit_addr
	[358] = { 2, { print_arg_ptr, print_arg_int } }, // setaudit_addr
	[359] = { 1, { print_arg_str } }, // auditctl
	[360] = { 5, { print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_int } }, // bsdthread_create
	[361] = { 4, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // bsdthread_terminate
	[362] = { 0, {  } }, // kqueue
	// kevent is special
	[364] = { 3, { print_arg_str, print_arg_int, print_arg_int } }, // lchown
	[366] = { 7, { print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // bsdthread_register
	[367] = { 0, {  } }, // workq_open
	[368] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // workq_kernreturn
	// kevent64 is special
	[370] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // __old_semwait_signal
	[371] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // __old_semwait_signal_nocancel
	[372] = { 0, {  } }, // thread_selfid
	[373] = { 4, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // ledger
	// kevent_qos is special
	[380] = { 4, { print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // __mac_execve
	[381] = { 3, { print_arg_ptr, print_arg_int, print_arg_ptr } }, // __mac_syscall
	[382] = { 2, { print_arg_ptr, print_arg_ptr } }, // __mac_get_file
	[383] = { 2, { print_arg_ptr, print_arg_ptr } }, // __mac_set_file
	[384] = { 2, { print_arg_ptr, print_arg_ptr } }, // __mac_get_link
	[385] = { 2, { print_arg_ptr, print_arg_ptr } }, // __mac_set_link
	[386] = { 1, { print_arg_ptr } }, // __mac_get_proc
	[387] = { 1, { print_arg_ptr } }, // __mac_set_proc
	[388] = { 2, { print_arg_int, print_arg_ptr } }, // __mac_get_fd
	[389] = { 2, { print_arg_int, print_arg_ptr } }, // __mac_set_fd
	[390] = { 2, { print_arg_int, print_arg_ptr } }, // __mac_get_pid
	[394] = { 6, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // pselect
	[395] = { 6, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // pselect_nocancel
	[396] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // read_nocancel
	[397] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // write_nocancel
	[398] = { 3, { print_arg_str, print_open_flags, print_arg_int } }, // open_nocancel
	[399] = { 1, { print_arg_int } }, // close_nocancel
	[400] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr } }, // wait4_nocancel
	[401] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // recvmsg_nocancel
	[402] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // sendmsg_nocancel
	[403] = { 6, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_ptr, print_arg_ptr } }, // recvfrom_nocancel
	[404] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // accept_nocancel
	[405] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // msync_nocancel
	[406] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // fcntl_nocancel
	[407] = { 5, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // select_nocancel
	[408] = { 1, { print_arg_int } }, // fsync_nocancel
	[409] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // connect_nocancel
	[410] = { 1, { print_arg_int } }, // sigsuspend_nocancel
	[411] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // readv_nocancel
	[412] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // writev_nocancel
	[413] = { 6, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // sendto_nocancel
	[414] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // pread_nocancel
	[415] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // pwrite_nocancel
	[416] = { 4, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // waitid_nocancel
	[417] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // poll_nocancel
	[418] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // msgsnd_nocancel
	[419] = { 5, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // msgrcv_nocancel
	[420] = { 1, { print_arg_ptr } }, // sem_wait_nocancel
	[421] = { 3, { print_arg_ptr, print_arg_int, print_arg_ptr } }, // aio_suspend_nocancel
	[422] = { 2, { print_arg_ptr, print_arg_ptr } }, // __sigwait_nocancel
	[423] = { 6, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // __semwait_signal_nocancel
	[424] = { 5, { print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_ptr } }, // __mac_mount
	[425] = { 2, { print_arg_ptr, print_arg_ptr } }, // __mac_get_mount
	[426] = { 5, { print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // __mac_getfsstat
	[427] = { 4, { print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int } }, // fsgetpath
	[428] = { 0, {  } }, // audit_session_self
	[429] = { 1, { print_arg_int } }, // audit_session_join
	[430] = { 2, { print_arg_int, print_arg_ptr } }, // fileport_makeport
	[431] = { 1, { print_arg_int } }, // fileport_makefd
	[432] = { 2, { print_arg_int, print_arg_ptr } }, // audit_session_port
	[433] = { 1, { print_arg_int } }, // pid_suspend
	[434] = { 1, { print_arg_int } }, // pid_resume
	[438] = { 6, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int } }, // shared_region_map_and_slide_np
	[439] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // kas_info
	[440] = { 5, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // memorystatus_control
	[441] = { 5, { print_arg_str, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int } }, // guarded_open_np
	[442] = { 2, { print_arg_int, print_arg_ptr } }, // guarded_close_np
	[443] = { 2, { print_arg_ptr, print_arg_int } }, // guarded_kqueue_np
	[444] = { 6, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr } }, // change_fdguard_np
	[445] = { 1, { print_arg_int } }, // usrctl
	[446] = { 3, { print_arg_int, print_arg_int, print_arg_ptr } }, // proc_rlimit_control
	[447] = { 8, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_ptr } }, // connectx
	[448] = { 3, { print_arg_int, print_arg_int, print_arg_int } }, // disconnectx
	[449] = { 2, { print_arg_int, print_arg_int } }, // peeloff
	[450] = { 4, { print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // socket_delegate
	[451] = { 6, { print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // telemetry
	[452] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // proc_uuid_policy
	[453] = { 1, { print_arg_ptr } }, // memorystatus_get_level
	[454] = { 2, { print_arg_int, print_arg_int } }, // system_override
	[455] = { 0, {  } }, // vfs_purge
	[456] = { 4, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // sfi_ctl
	[457] = { 4, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr } }, // sfi_pidctl
	[458] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // coalition
	[459] = { 4, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // coalition_info
	[460] = { 3, { print_arg_ptr, print_arg_int, print_arg_ptr } }, // necp_match_policy
	[461] = { 5, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // getattrlistbulk
	[462] = { 5, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int } }, // clonefileat
	[463] = { 4, { print_arg_int, print_arg_str, print_open_flags, print_arg_int } }, // openat
	[464] = { 4, { print_arg_int, print_arg_str, print_open_flags, print_arg_int } }, // openat_nocancel
	[465] = { 4, { print_arg_int, print_arg_str, print_arg_int, print_arg_str } }, // renameat
	[466] = { 4, { print_arg_int, print_arg_str, print_arg_int, print_arg_int } }, // faccessat
	[467] = { 4, { print_arg_int, print_arg_str, print_arg_int, print_arg_int } }, // fchmodat
	[468] = { 5, { print_arg_int, print_arg_str, print_arg_int, print_arg_int, print_arg_int } }, // fchownat
	[469] = { 4, { print_arg_int, print_arg_str, print_arg_ptr, print_arg_int } }, // fstatat
	[470] = { 4, { print_arg_int, print_arg_str, print_arg_ptr, print_arg_int } }, // fstatat64
	[471] = { 5, { print_arg_int, print_arg_str, print_arg_int, print_arg_str, print_arg_int } }, // linkat
	[472] = { 3, { print_arg_int, print_arg_str, print_arg_int } }, // unlinkat
	[473] = { 4, { print_arg_int, print_arg_str, print_arg_ptr, print_arg_int } }, // readlinkat
	[474] = { 3, { print_arg_str, print_arg_int, print_arg_str } }, // symlinkat
	[475] = { 3, { print_arg_int, print_arg_str, print_arg_int } }, // mkdirat
	[476] = { 6, { print_arg_int, print_arg_str, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // getattrlistat
	[477] = { 2, { print_arg_int, print_arg_int } }, // proc_trace_log
	[478] = { 4, { print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // bsdthread_ctl
	[479] = { 3, { print_arg_ptr, print_arg_ptr, print_arg_int } }, // openbyid_np
	[480] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // recvmsg_x
	[481] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // sendmsg_x
	[482] = { 0, {  } }, // thread_selfusage
	[483] = { 3, { print_arg_int, print_arg_ptr, print_arg_ptr } }, // csrctl
	[484] = { 7, { print_arg_str, print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // guarded_open_dprotected_np
	[485] = { 4, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int } }, // guarded_write_np
	[486] = { 5, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int, print_arg_int } }, // guarded_pwrite_np
	[487] = { 4, { print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_int } }, // guarded_writev_np
	[488] = { 5, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int } }, // renameatx_np
	[489] = { 5, { print_arg_ptr, print_arg_int, print_arg_int, print_arg_int, print_arg_int } }, // mremap_encrypted
	[490] = { 2, { print_arg_ptr, print_arg_int } }, // netagent_trigger
	[491] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // stack_snapshot_with_config
	[492] = { 3, { print_arg_ptr, print_arg_int, print_arg_int } }, // microstackshot
	[493] = { 4, { print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int } }, // grab_pgo_data
	[494] = { 5, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr } }, // persona
	[499] = { 4, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // work_interval_ctl
	[500] = { 2, { print_arg_ptr, print_arg_int } }, // getentropy
	[501] = { 1, { print_arg_int } }, // necp_open
	[502] = { 6, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_ptr, print_arg_int } }, // necp_client_action
	[515] = { 4, { print_arg_int, print_arg_ptr, print_arg_int, print_arg_int } }, // ulock_wait
	[516] = { 3, { print_arg_int, print_arg_ptr, print_arg_int } }, // ulock_wake
	[517] = { 4, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int } }, // fclonefileat
	[518] = { 6, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_ptr, print_arg_ptr, print_arg_int } }, // fs_snapshot
	[520] = { 7, { print_arg_int, print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_str, print_arg_int } }, // terminate_with_payload
	[521] = { 6, { print_arg_int, print_arg_int, print_arg_ptr, print_arg_int, print_arg_str, print_arg_int } }, // abort_with_payload
};

static void print_args(xtrace::String* log, int nr, void* args[])
{
	int cnt = args_info[nr].args_cnt;
	for (int i = 0; i < cnt; i++)
	{
		if (i > 0)
			log->append(", ");
		(*args_info[nr].print_arg[i])(log, args[i]);
	}
}


extern "C"
void darling_bsd_syscall_entry_print(int nr, void* args[])
{
	xtrace::String log;
#if __i386__
	// get rid of some info in the upper bytes that we don't need
	nr = (int)((unsigned int)nr & 0xffff);
#endif

	handle_generic_entry(&log, bsd_defs, "bsd", nr, args);

	if (nr == 1 || nr == 59)
	{
		// For exit() or execve(), print an extra newline,
		// as we're likely not going to see the return.
		log.append("\n");
	}

	if (log.size() > 0) {
		xtrace_log("%s", log.c_str());
		log.clear();
	}
}

extern "C"
void darling_bsd_syscall_exit_print(uintptr_t retval)
{
	xtrace::String log;
	handle_generic_exit(&log, bsd_defs, "bsd", retval, 0);

	if (log.size() > 0) {
		xtrace_log("%s", log.c_str());
		log.clear();
	}
}

const char* error_strings[128] = {
	[1] = "EPERM",
	[2] = "ENOENT",
	[3] = "ESRCH",
	[4] = "EINTR",
	[5] = "EIO",
	[6] = "ENXIO",
	[7] = "E2BIG",
	[8] = "ENOEXEC",
	[9] = "EBADF",
	[10] = "ECHILD",
	[11] = "EDEADLK",
	[12] = "ENOMEM",
	[13] = "EACCES",
	[14] = "EFAULT",
	[15] = "ENOTBLK",
	[16] = "EBUSY",
	[17] = "EEXIST",
	[18] = "EXDEV",
	[19] = "ENODEV",
	[20] = "ENOTDIR",
	[21] = "EISDIR",
	[22] = "EINVAL",
	[23] = "ENFILE",
	[24] = "EMFILE",
	[25] = "ENOTTY",
	[26] = "ETXTBSY",
	[27] = "EFBIG",
	[28] = "ENOSPC",
	[29] = "ESPIPE",
	[30] = "EROFS",
	[31] = "EMLINK",
	[32] = "EPIPE",
	[33] = "EDOM",
	[34] = "ERANGE",
	[35] = "EAGAIN",
	[36] = "EINPROGRESS",
	[37] = "EALREADY",
	[38] = "ENOTSOCK",
	[39] = "EDESTADDRREQ",
	[40] = "EMSGSIZE",
	[41] = "EPROTOTYPE",
	[42] = "ENOPROTOOPT",
	[43] = "EPROTONOSUPPORT",
	[44] = "ESOCKTNOSUPPORT",
	[45] = "ENOTSUP",
	[46] = "EPFNOSUPPORT",
	[47] = "EAFNOSUPPORT",
	[48] = "EADDRINUSE",
	[49] = "EADDRNOTAVAIL",
	[50] = "ENETDOWN",
	[51] = "ENETUNREACH",
	[52] = "ENETRESET",
	[53] = "ECONNABORTED",
	[54] = "ECONNRESET",
	[55] = "ENOBUFS",
	[56] = "EISCONN",
	[57] = "ENOTCONN",
	[58] = "ESHUTDOWN",
	[59] = "ETOOMANYREFS",
	[60] = "ETIMEDOUT",
	[61] = "ECONNREFUSED",
	[62] = "ELOOP",
	[63] = "ENAMETOOLONG",
	[64] = "EHOSTDOWN",
	[65] = "EHOSTUNREACH",
	[66] = "ENOTEMPTY",
	[67] = "EPROCLIM",
	[68] = "EUSERS",
	[69] = "EDQUOT",
	[70] = "ESTALE",
	[71] = "EREMOTE",
	[72] = "EBADRPC",
	[73] = "ERPCMISMATCH",
	[74] = "EPROGUNAVAIL",
	[75] = "EPROGMISMATCH",
	[76] = "EPROCUNAVAIL",
	[77] = "ENOLCK",
	[78] = "ENOSYS",
	[79] = "EFTYPE",
	[80] = "EAUTH",
	[81] = "ENEEDAUTH",
	[82] = "EPWROFF",
	[83] = "EDEVERR",
	[84] = "EOVERFLOW",
	[85] = "EBADEXEC",
	[86] = "EBADARCH",
	[87] = "ESHLIBVERS",
	[88] = "EBADMACHO",
	[89] = "ECANCELED",
	[90] = "EIDRM",
	[91] = "ENOMSG",
	[92] = "EILSEQ",
	[93] = "ENOATTR",
	[94] = "EBADMSG",
	[95] = "EMULTIHOP",
	[96] = "ENODATA",
	[97] = "ENOLINK",
	[98] = "ENOSR",
	[99] = "ENOSTR",
	[100] = "EPROTO",
	[101] = "ETIME",
	[102] = "EOPNOTSUPP",
	[103] = "ENOPOLICY",
	[104] = "ENOTRECOVERABLE",
	[105] = "EOWNERDEAD",
	[106] = "EQFULL",
};

static void print_errno_num(xtrace::String* log, int nr, uintptr_t rv)
{
	intptr_t v = (intptr_t)rv;
	if (v >= 0 || v < -4095)
	{
		log->append_format("%ld", rv);
	}
	else
		print_errno(log, nr, rv);
}

static void print_errno_ptr(xtrace::String* log, int nr, uintptr_t rv)
{
	intptr_t v = (intptr_t)rv;
	if (v >= 0 || v < -4095)
	{
		log->append_format("%p", (void*) rv);
	}
	else
		print_errno(log, nr, rv);
}

static void print_errno(xtrace::String* log, int nr, uintptr_t rv)
{
	const char* error = NULL;
	intptr_t v = (intptr_t) rv;
	if (-v < 128)
		error = error_strings[-v];
	if (error != NULL)
		log->append_format("%s", error);
	else
		log->append_format("%ld", v);
}

static const char* const filter_names[] = {
	"EVFILT_READ",
	"EVFILT_WRITE",
	"EVFILT_AIO",
	"EVFILT_VNODE",
	"EVFILT_PROC",
	"EVFILT_SIGNAL",
	"EVFILT_TIMER",
	"EVFILT_MACHPORT",
	"EVFILT_FS",
	"EVFILT_USER",
	NULL,
	"EVFILT_VM",
	"EVFILT_SOCK",
	"EVFILT_MEMORYSTATUS",
	"EVFILT_EXCEPT",
	NULL,
	"EVFILT_WORKLOOP",
};

static const char* const signal_names[] = {
	"SIGHUP",
	"SIGINT",
	"SIGQUIT",
	"SIGILL",
	"SIGTRAP",
	"SIGABRT",
	"SIGEMT",
	"SIGFPE",
	"SIGKILL",
	"SIGBUS",
	"SIGSEGV",
	"SIGSYS",
	"SIGPIPE",
	"SIGALRM",
	"SIGTERM",
	"SIGURG",
	"SIGSTOP",
	"SIGTSTP",
	"SIGCONT",
	"SIGCHLD",
	"SIGTTIN",
	"SIGTTOU",
	"SIGIO",
	"SIGXCPU",
	"SIGXFSZ",
	"SIGVTALR",
	"SIGPROF",
	"SIGWINCH",
	"SIGINFO",
	"SIGUSR1",
	"SIGUSR2",
};

static const struct {
	uint16_t flag;
	const char* name;
} kevent_flag_names[] = {
#define FLAG(_name) { _name, #_name }
	FLAG(EV_ADD),
	FLAG(EV_ENABLE),
	FLAG(EV_DISABLE),
	FLAG(EV_DELETE),
	FLAG(EV_RECEIPT),
	FLAG(EV_ONESHOT),
	FLAG(EV_CLEAR),
	FLAG(EV_DISPATCH),
	FLAG(EV_UDATA_SPECIFIC),
	FLAG(EV_FLAG0),
	FLAG(EV_FLAG1),
	FLAG(EV_EOF),
	FLAG(EV_ERROR),
#undef KEVENT_FLAG
};

static const struct {
	uint32_t flag;
	const char* name;
} kevent_filter_flag_names[][16] = {
#define FLAG(_name) { _name, #_name }
	[~EVFILT_READ] = {
		FLAG(NOTE_LOWAT),
	},
	[~EVFILT_EXCEPT] = {
		FLAG(NOTE_OOB),
	},
	[~EVFILT_VNODE] = {
		FLAG(NOTE_DELETE),
		FLAG(NOTE_WRITE),
		FLAG(NOTE_EXTEND),
		FLAG(NOTE_ATTRIB),
		FLAG(NOTE_LINK),
		FLAG(NOTE_RENAME),
		FLAG(NOTE_REVOKE),
		FLAG(NOTE_NONE),
		FLAG(NOTE_FUNLOCK),
	},
	[~EVFILT_PROC] = {
		FLAG(NOTE_EXIT),
		FLAG(NOTE_FORK),
		FLAG(NOTE_EXEC),
		FLAG(NOTE_REAP),
		FLAG(NOTE_SIGNAL),
		FLAG(NOTE_EXITSTATUS),
		FLAG(NOTE_EXIT_DETAIL),
	},
	[~EVFILT_TIMER] = {
		FLAG(NOTE_SECONDS),
		FLAG(NOTE_USECONDS),
		FLAG(NOTE_NSECONDS),
		FLAG(NOTE_MACHTIME),
		FLAG(NOTE_ABSOLUTE),
		FLAG(NOTE_MACH_CONTINUOUS_TIME),
		FLAG(NOTE_CRITICAL),
		FLAG(NOTE_BACKGROUND),
		FLAG(NOTE_LEEWAY),
		FLAG(NOTE_TRACK),
		FLAG(NOTE_TRACKERR),
		FLAG(NOTE_CHILD),
	},
	[~EVFILT_SOCK] = {
		FLAG(NOTE_CONNRESET),
		FLAG(NOTE_READCLOSED),
		FLAG(NOTE_WRITECLOSED),
		FLAG(NOTE_TIMEOUT),
		FLAG(NOTE_NOSRCADDR),
		FLAG(NOTE_IFDENIED),
		FLAG(NOTE_SUSPEND),
		FLAG(NOTE_RESUME),
		FLAG(NOTE_KEEPALIVE),
		FLAG(NOTE_ADAPTIVE_WTIMO),
		FLAG(NOTE_ADAPTIVE_RTIMO),
		FLAG(NOTE_CONNECTED),
		FLAG(NOTE_DISCONNECTED),
		FLAG(NOTE_CONNINFO_UPDATED),
		FLAG(NOTE_NOTIFY_ACK),
	},
	[~EVFILT_MACHPORT] = {
		FLAG(MACH_RCV_MSG),
	},
#undef FLAG
};

static void print_kevent_common(xtrace::String* log, int16_t filter, uintptr_t ident, uint16_t flags, uint32_t fflags, intptr_t data, void* udata) {
	int filt_index = ~filter;
	bool printed_something = false;

	log->append_format("%s { ident = ", (filt_index < 0 || filt_index >= sizeof(filter_names) / sizeof(*filter_names)) ? "EVFILT_UNKNOWN" : filter_names[filt_index]);

	switch (filter) {
		case EVFILT_READ:
		case EVFILT_WRITE:
		case EVFILT_EXCEPT:
		case EVFILT_VNODE:
		case EVFILT_SOCK:
			log->append_format("fd %lu", ident);
			break;

		case EVFILT_PROC:
			log->append_format("pid %lu", ident);
			break;

		case EVFILT_SIGNAL:
			log->append_format("signal %s (%lu)", (ident < sizeof(signal_names) / sizeof(*signal_names)) ? signal_names[ident] : "SIGUNKNOWN", ident);
			break;

		case EVFILT_TIMER:
			log->append_format("timer %lu", ident);
			break;

		case EVFILT_MACHPORT:
			// officially, only portsets can be used with EVFILT_MACHPORT. however, Apple introduced support for single ports in 10.13 or something around that time.
			log->append_format("port/portset %lu", ident);
			break;

		case EVFILT_FS:
		case EVFILT_USER:
		case EVFILT_VM:
		case EVFILT_MEMORYSTATUS:
		case EVFILT_WORKLOOP:
			// notes:
			//   * EVFILT_VM is unsupported on macOS.
			//   * do EVFILT_FS, EVFILT_MEMORYSTATUS, and EVFILT_WORKLOOP even use `ident`?
			log->append_format("%lu", ident);
			break;

		default:
			log->append_format("%lu", ident);
			break;
	}

	log->append(", flags = ");

	for (size_t i = 0; i < sizeof(kevent_flag_names) / sizeof(*kevent_flag_names); ++i) {
		if ((flags & kevent_flag_names[i].flag) == 0) {
			continue;
		}

		if (!printed_something) {
			printed_something = true;
		} else {
			log->append("|");
		}

		log->append_format("%s", kevent_flag_names[i].name);
	}

	log->append_format("%s(0x%x), fflags = ", printed_something ? " " : "", flags);

	printed_something = false;

	if (filt_index < sizeof(kevent_filter_flag_names) / sizeof(*kevent_filter_flag_names)) {
		for (size_t i = 0; i < sizeof(*kevent_filter_flag_names) / sizeof(**kevent_filter_flag_names); ++i) {
			if (!kevent_filter_flag_names[filt_index][i].name) {
				break;
			}

			if ((fflags & kevent_filter_flag_names[filt_index][i].flag) == 0) {
				continue;
			}

			if (!printed_something) {
				printed_something = true;
			} else {
				log->append("|");
			}

			log->append_format("%s", kevent_filter_flag_names[filt_index][i].name);
		}
	}

	log->append_format("%s(0x%x), udata = %p, data = 0x%lx", printed_something ? " " : "", fflags, udata, data);
};

static void print_kevent_structure(xtrace::String* log, const struct kevent* event) {
	print_kevent_common(log, event->filter, event->ident, event->flags, event->fflags, event->data, event->udata);
	log->append(" }");
};

static void print_kevent64_structure(xtrace::String* log, const struct kevent64_s* event) {
	print_kevent_common(log, event->filter, event->ident, event->flags, event->fflags, event->data, (void*)(uintptr_t)event->udata);
	log->append_format(", ext[0] = 0x%llx, ext[1] = 0x%llx }", event->ext[0], event->ext[1]);
};

static void print_kevent_qos_structure(xtrace::String* log, const struct kevent_qos_s* event) {
	print_kevent_common(log, event->filter, event->ident, event->flags, event->fflags, event->data, (void*)(uintptr_t)event->udata);
	log->append_format(", ext[0] = 0x%llx, ext[1] = 0x%llx, ext[2] = 0x%llx, ext[3] = 0x%llx, qos = %d, xflags = 0x%x }", event->ext[0], event->ext[1], event->ext[2], event->ext[3], event->qos, event->xflags);
};

DEFINE_XTRACE_TLS_VAR(void*, kevent_stored_list, NULL, NULL);
DEFINE_XTRACE_TLS_VAR(void*, kevent64_stored_list, NULL, NULL);
DEFINE_XTRACE_TLS_VAR(void*, kevent_qos_stored_list, NULL, NULL);

enum class kevent_type {
	kevent,
	kevent64,
	kevent_qos,
};

static void print_kevent_return_common(xtrace::String* log, int nr, uintptr_t rv, kevent_type type) {
	void* event_list;
	int ret = (intptr_t)rv;

	switch (type) {
		case kevent_type::kevent:
			event_list = get_kevent_stored_list();
			set_kevent_stored_list(NULL);
			break;
		case kevent_type::kevent64:
			event_list = get_kevent64_stored_list();
			set_kevent64_stored_list(NULL);
			break;
		case kevent_type::kevent_qos:
			event_list = get_kevent_qos_stored_list();
			set_kevent_qos_stored_list(NULL);
			break;
	}

	if (ret < 0) {
		print_errno(log, nr, rv);
		return;
	}

	log->append_format("%d events {", ret);

	for (int i = 0; i < ret; ++i) {
		if (i == 0) {
			log->append(" ");
		} else {
			log->append(", ");
		}

		switch (type) {
			case kevent_type::kevent:
				print_kevent_structure(log, &((struct kevent*)event_list)[i]);
				break;
			case kevent_type::kevent64:
				print_kevent64_structure(log, &((struct kevent64_s*)event_list)[i]);
				break;
			case kevent_type::kevent_qos:
				print_kevent_qos_structure(log, &((struct kevent_qos_s*)event_list)[i]);
				break;
		}
	}

	log->append_format("%s}", ret > 0 ? " " : "");
};

static void print_kevent_return(xtrace::String* log, int nr, uintptr_t rv) {
	print_kevent_return_common(log, nr, rv, kevent_type::kevent);
};

static void print_kevent_args(xtrace::String* log, int nr, void* args[]) {
	int kq = (intptr_t)args[0];
	const struct kevent* change_list = (const struct kevent*)args[1];
	int nchanges = (intptr_t)args[2];
	struct kevent* event_list = (struct kevent*)args[3];
	int nevents = (intptr_t)args[4];
	const struct timespec* timeout = (const struct timespec*)args[5];

	set_kevent_stored_list(event_list);

	log->append_format("%d, change_list = {", kq);

	for (int i = 0; i < nchanges; ++i) {
		if (i == 0) {
			log->append(" ");
		} else {
			log->append(", ");
		}
		print_kevent_structure(log, &change_list[i]);
	}

	log->append_format("%s}, nchanges = %d, event_list = %p, nevents = %d, timeout = ", nchanges > 0 ? " " : "", nchanges, event_list, nevents);

	print_timespec(log, timeout);
};

static void print_kevent64_return(xtrace::String* log, int nr, uintptr_t rv) {
	print_kevent_return_common(log, nr, rv, kevent_type::kevent64);
};

static struct {
	unsigned int flag;
	const char* name;
} kevent_call_flags[] = {
#define FLAG(_name) { _name, #_name }
	FLAG(KEVENT_FLAG_NONE),
	FLAG(KEVENT_FLAG_IMMEDIATE),
	FLAG(KEVENT_FLAG_ERROR_EVENTS),
	FLAG(KEVENT_FLAG_STACK_DATA),
	FLAG(KEVENT_FLAG_WORKQ),
	FLAG(KEVENT_FLAG_WORKQ_MANAGER),
	FLAG(KEVENT_FLAG_WORKLOOP),
	FLAG(KEVENT_FLAG_PARKING),
	FLAG(KEVENT_FLAG_WORKLOOP_SERVICER_ATTACH),
	FLAG(KEVENT_FLAG_WORKLOOP_SERVICER_DETACH),
	FLAG(KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST),
	FLAG(KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST),
	FLAG(KEVENT_FLAG_WORKLOOP_NO_WQ_THREAD),
#undef FLAG
};

static void print_kevent64_args(xtrace::String* log, int nr, void* args[]) {
	int kq = (intptr_t)args[0];
	const struct kevent64_s* change_list = (const struct kevent64_s*)args[1];
	int nchanges = (intptr_t)args[2];
	struct kevent64_s* event_list = (struct kevent64_s*)args[3];
	int nevents = (intptr_t)args[4];
	unsigned int flags = (uintptr_t)args[5];
	const struct timespec* timeout = (const struct timespec*)args[6];
	bool printed_something = false;

	set_kevent64_stored_list(event_list);

	log->append_format("%d, change_list = {", kq);

	for (int i = 0; i < nchanges; ++i) {
		if (i == 0) {
			log->append(" ");
		} else {
			log->append(", ");
		}
		print_kevent64_structure(log, &change_list[i]);
	}

	log->append_format("%s}, nchanges = %d, event_list = %p, nevents = %d, flags = ", nchanges > 0 ? " " : "", nchanges, event_list, nevents);

	for (size_t i = 0; i < sizeof(kevent_call_flags) / sizeof(*kevent_call_flags); ++i) {
		if ((flags & kevent_call_flags[i].flag) == 0) {
			continue;
		}

		if (!printed_something) {
			printed_something = true;
		} else {
			log->append("|");
		}

		log->append_format("%s", kevent_call_flags[i].name);
	}

	if (!printed_something) {
		log->append("0");
	}

	log->append(", timeout = ");

	print_timespec(log, timeout);
};

static void print_kevent_qos_return(xtrace::String* log, int nr, uintptr_t rv) {
	print_kevent_return_common(log, nr, rv, kevent_type::kevent_qos);
};

static void print_kevent_qos_args(xtrace::String* log, int nr, void* args[]) {
	int kq = (intptr_t)args[0];
	const struct kevent_qos_s* change_list = (const struct kevent_qos_s*)args[1];
	int nchanges = (intptr_t)args[2];
	struct kevent_qos_s* event_list = (struct kevent_qos_s*)args[3];
	int nevents = (intptr_t)args[4];
	void* data_out = args[5];
	size_t* data_available = (size_t*)args[6];
	unsigned int flags = (uintptr_t)args[7];
	bool printed_something = false;

	set_kevent_qos_stored_list(event_list);

	log->append_format("%d, change_list = {", kq);

	for (int i = 0; i < nchanges; ++i) {
		if (i == 0) {
			log->append(" ");
		} else {
			log->append(", ");
		}
		print_kevent_qos_structure(log, &change_list[i]);
	}

	log->append_format("%s}, nchanges = %d, event_list = %p, nevents = %d, data_out = %p, data_available = %p (%ld), flags = ", nchanges > 0 ? " " : "", nchanges, event_list, nevents, data_out, data_available, data_available ? *data_available : 0);

	for (size_t i = 0; i < sizeof(kevent_call_flags) / sizeof(*kevent_call_flags); ++i) {
		if ((flags & kevent_call_flags[i].flag) == 0) {
			continue;
		}

		if (!printed_something) {
			printed_something = true;
		} else {
			log->append("|");
		}

		log->append_format("%s", kevent_call_flags[i].name);
	}

	if (!printed_something) {
		log->append("0");
	}
};

static void print_timespec(xtrace::String* log, const struct timespec* timespec) {
	if (timespec) {
		log->append_format("(%ld s, %ld ns)", timespec->tv_sec, timespec->tv_nsec);
	} else {
		log->append("NULL");
	}
};

static void print_timeval(xtrace::String* log, struct timeval* timeval) {
	if (timeval) {
		log->append_format("(%ld s, %d ns)", timeval->tv_sec, timeval->tv_usec);
	} else {
		log->append("NULL");
	}
};

struct select_fdsets {
	fd_set* readfds;
	fd_set* writefds;
	fd_set* exceptfds;
	int max_fd;
};

DEFINE_XTRACE_TLS_VAR(select_fdsets, stored_select_fdsets, ((struct select_fdsets){NULL, NULL, NULL, -1}), NULL);

static void print_fdset(xtrace::String* log, const fd_set* set, int max_fd) {
	bool isFirst = true;
	log->append("{");
	if (set) {
		for (size_t index = 0; index < sizeof(set->fds_bits) / sizeof(*set->fds_bits); ++index) {
			bool shouldBreak = false;
			for (size_t bit = 0; bit < sizeof(*set->fds_bits) * 8; ++bit) {
				int fd = (index * sizeof(*set->fds_bits) * 8) + bit;
				if (fd >= max_fd) {
					shouldBreak = true;
					break;
				}
				if ((set->fds_bits[index] & (1U << bit)) != 0) {
					if (isFirst) {
						isFirst = false;
						log->append(" ");
					} else {
						log->append(", ");
					}
					log->append_format("%d", fd);
				}
			}
			if (shouldBreak) {
				break;
			}
		}
	}
	if (!isFirst) {
		log->append(" ");
	}
	log->append("}");
};

static void print_select_return(xtrace::String* log, int nr, uintptr_t rv) {
	auto stored = get_ptr_stored_select_fdsets();
	int ret = (int)rv;
	bool isFirst = true;

	if (ret < 0) {
		print_errno(log, nr, rv);
	} else {
		log->append_format("%d descriptors: ", ret);

		if (stored->readfds) {
			if (isFirst) {
				isFirst = false;
			} else {
				log->append(", ");
			}
			log->append("read ");
			print_fdset(log, stored->readfds, stored->max_fd);
		}

		if (stored->writefds) {
			if (isFirst) {
				isFirst = false;
			} else {
				log->append(", ");
			}
			log->append("write ");
			print_fdset(log, stored->writefds, stored->max_fd);
		}

		if (stored->exceptfds) {
			if (isFirst) {
				isFirst = false;
			} else {
				log->append(", ");
			}
			log->append("except ");
			print_fdset(log, stored->exceptfds, stored->max_fd);
		}
	}

	stored->readfds = NULL;
	stored->writefds = NULL;
	stored->exceptfds = NULL;
	stored->max_fd = -1;
};

static void print_select_args(xtrace::String* log, int nr, void* args[]) {
	auto stored = get_ptr_stored_select_fdsets();

	int nfds = (intptr_t)args[0];
	fd_set* readfds = (fd_set*)args[1];
	fd_set* writefds = (fd_set*)args[2];
	fd_set* exceptfds = (fd_set*)args[3];
	struct timeval* timeout = (struct timeval*)args[4];

	log->append_format("nfds = %d, readfds = ", nfds);
	print_fdset(log, readfds, nfds);
	log->append(", writefds = ");
	print_fdset(log, writefds, nfds);
	log->append(", exceptfds = ");
	print_fdset(log, exceptfds, nfds);
	log->append(", timeout = ");
	print_timeval(log, timeout);

	stored->readfds = readfds;
	stored->writefds = writefds;
	stored->exceptfds = exceptfds;
	stored->max_fd = nfds;
};
