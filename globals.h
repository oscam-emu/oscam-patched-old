#ifndef GLOBALS_H_
#define GLOBALS_H_

#define _GNU_SOURCE // needed for PTHREAD_MUTEX_RECURSIVE on some plattforms and maybe other things; do not remove
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include <pwd.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <termios.h>
#include <inttypes.h>
#include <sys/utsname.h>

#if !defined(__APPLE__)
#include <sys/sysmacros.h>
#endif

/*
 * The following hack is taken from Linux: include/linux/kconfig.h
 * Original comment follows:
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky. Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0). Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val

#include "config.h"

#if defined(WITH_SSL) && !defined(WITH_LIBCRYPTO)
# define WITH_LIBCRYPTO 1
#endif

#if defined(__CYGWIN__) || defined(__arm__) || defined(__SH4__) || defined(__MIPS__) || defined(__MIPSEL__) || defined(__powerpc__)
# define CS_LOGFILE "/dev/tty"
#endif

#if defined(__AIX__) || defined(__SGI__) || defined(__OSF__) || defined(__HPUX__) || defined(__SOLARIS__) || defined(__APPLE__)
# define NEED_DAEMON
#endif

#if defined(__AIX__) || defined(__SGI__) || defined(__OSF__) || defined(__HPUX__) || defined(__SOLARIS__) || defined(__CYGWIN__)
# define NO_ENDIAN_H
#endif

#if defined(__AIX__) || defined(__SGI__)
# define socklen_t unsigned long
#endif

#if defined(__SOLARIS__) || defined(__FreeBSD__) || defined(__OpenBSD__)
# define BSD_COMP
#endif

#if defined(__HPUX__)
# define _XOPEN_SOURCE_EXTENDED
#endif

#if (defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)) && !defined(s6_addr32)
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#ifdef __ANDROID__
#ifndef in_port_t
#define in_port_t uint16_t
#endif
#define tcdrain(fd) ioctl(fd, TCSBRK, 1)
#endif

#ifdef __uClinux__
#define fork() 0
#endif

// Prevent warnings about openssl functions. Apple may consider 'openssl'
// deprecated but changing perfectly working portable code just because they
// introduced some proprietary API is not going to happen.
#if defined(__APPLE__)
#define __AVAILABILITY_MACROS_USES_AVAILABILITY 0
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_6
#endif

#include "cscrypt/aes.h"

#ifdef IPV6SUPPORT
#define IN_ADDR_T struct in6_addr
#define SOCKADDR sockaddr_storage
#define ADDR_ANY in6addr_any
#define DEFAULT_AF AF_INET6
#else
#define IN_ADDR_T in_addr_t
#define SOCKADDR sockaddr_in
#define ADDR_ANY INADDR_ANY
#define DEFAULT_AF AF_INET
#endif

#ifndef NO_ENDIAN_H
#if defined(__APPLE__)
#include <machine/endian.h>
#define __BYTE_ORDER __DARWIN_BYTE_ORDER
#define __BIG_ENDIAN    __DARWIN_BIG_ENDIAN
#define __LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>
#define __BYTE_ORDER _BYTE_ORDER
#define __BIG_ENDIAN    _BIG_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
#include <endian.h>
#include <byteswap.h>
#endif
#endif

/* ===========================
 *			macros
 * =========================== */
// Prevent use of unsafe functions (doesn't work for MacOSX)
#if !defined(__APPLE__)
#define strcpy(a,b) UNSAFE_STRCPY_USE_CS_STRNCPY_INSTEAD()
#define sprintf(a,...) UNSAFE_SPRINTF_USE_SNPRINTF_INSTEAD()
#define strtok(a,b,c) UNSAFE_STRTOK_USE_STRTOK_R_INSTEAD()
#define gmtime(a) UNSAFE_GMTIME_NOT_THREADSAFE_USE_CS_GMTIME_R()
#define localtime(a) UNSAFE_LOCALTIME_NOT_THREADSAFE_USE_LOCALTIME_R()
#define asctime(a) UNSAFE_ASCTIME_NOT_THREADSAFE_USE_ASCTIME_R()
#define ctime(a) UNSAFE_CTIME_NOT_THREADSAFE_USE_CS_CTIME_R()
#define gethostbyaddr(a,b,c) UNSAFE_GETHOSTBYADDR_NOT_THREADSAFE_USE_GETADDRINFO()
#define gethostent(a) UNSAFE_GETHOSTENT_NOT_THREADSAFE()
#define getprotobyname(a) UNSAFE_GETPROTOBYNAME_NOT_THREADSAFE_USE_GETPROTOBYNAME_R()
#define getservbyname(a,b) UNSAFE_GETSERVBYNAME_NOT_THREADSAFE_USE_GETSERVBYNAME_R()
#define getservbyport(a,b) UNSAFE_GETSERVBYPORT_NOT_THREADSAFE_USE_GETSERVBYPORT_R()
#define getservent() UNSAFE_GETSERVENT_NOT_THREADSAFE_USE_GETSERVENT_R()
#define getnetbyname(a) UNSAFE_GETNETBYNAME_NOT_THREADSAFE_USE_GETNETBYNAME_R
#define getnetbyaddr(a,b) UNSAFE_GETNETBYADDR_NOT_THREADSAFE_USE_GETNETBYADDR_R
#define getnetent() UNSAFE_GETNETENT_NOT_THREADSAFE_USE_GETNETENT_R
#define getrpcbyname(a) UNSAFE_GETRPCBYNAME_NOT_THREADSAFE_USE_GETRPCBYNAME_R
#define getrpcbynumber(a) UNSAFE_GETRPCBYNUMBER_NOT_THREADSAFE_USE_GETRPCBYNUMBER_R
#define getrpcent() UNSAFE_GETRPCENT_NOT_THREADSAFE_USE_GETRPCENT_R
#define ctermid(a) UNSAFE_CTERMID_NOT_THREADSAFE_USE_CTERMID_R
#define tmpnam(a) UNSAFE_TMPNAM_NOT_THREADSAFE
#define tempnam(a,b) UNSAFE_TEMPNAM_NOT_THREADSAFE
#define getlogin() UNSAFE_GETLOGIN_NOT_THREADSAFE_USE_GETLOGIN_R
#define getpwnam(a) UNSAFE_GETPWNAM_NOT_THREADSAFE_USE_GETPWNAM_R
#define getpwent() UNSAFE_GETPWENT_NOT_THREADSAFE_USE_GETPWENT_R
#define fgetpwent(a) UNSAFE_FGETPWENT_NOT_THREADSAFE_USE_FGETPWENT_R
#ifndef __ANDROID__
#define getpwuid(a) UNSAFE_GETPWUID_NOT_THREADSAFE_USE_GETPWUID_R
#endif
#define getspent() UNSAFE_GETSPENT_NOT_THREADSAFE_USE_GETSPENT_R
#define getspnam(a) UNSAFE_GETSPNAM_NOT_THREADSAFE_USE_GETSPNAM_R
#define fgetspent(a) UNSAFE_FGETSPENT_NOT_THREADSAFE_USE_FGETSPENT_R
#define getgrnam(a) UNSAFE_GETGRNAM_NOT_THREADSAFE_USE_GETGRNAM_R
#define getgrent() UNSAFE_GETGRENT_NOT_THREADSAFE_USE_GETGRENT_R
#define getgrgid(a) UNSAFE_GETGRGID_NOT_THREADSAFE_USE_GETGRGID_R
#define fgetgrent() UNSAFE_FGETGRENT_NOT_THREADSAFE_USE_FGETGRGID_R
#define fcvt(a,b,c,d) UNSAFE_FCVT_NOT_THREADSAFE_AND_DEPRECATED
#define ecvt(a,b,c,d) UNSAFE_ECVT_NOT_THREADSAFE_AND_DEPRECATED
#define gcvt(a,b,c) UNSAFE_GCVT_NOT_THREADSAFE_AND_DEPRECATED
#define strptime(a,b,c) STRPTIME_NOT_EXISTS_ON_SOME_DM500_DB2()
#define ftime(a) FTIME_DEPRECATED()
#define timegm(a) TIMEGM_GNU_SPECIFIC_USE_CS_TIMEGM
#endif

#ifdef UNUSED
#elif __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#if __GNUC__ >= 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
# define MUST_CHECK_RESULT __attribute__((warn_unused_result))
#endif

#ifdef OK
#undef OK
#endif

#ifdef ERROR
#undef ERROR
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifdef WITH_DEBUG
# define call(arg) \
	if(arg) \
	{ \
		cs_log_dbg(D_TRACE, "ERROR, function call %s returns error.",#arg); \
			return ERROR; \
	}
#else
# define call(arg) \
	if(arg) \
	{ \
		return ERROR; \
	}
#endif

// checking if (X) free(X) unneccessary since freeing a null pointer doesnt do anything
#define NULLFREE(X) {if (X) {void *tmpX=X; X=NULL; free(tmpX); }}

#ifdef __CYGWIN__
#define cs_recv(a,b,c,d) cygwin_recv(a,b,c,d)
#else
#define cs_recv(a,b,c,d) recv(a,b,c,d)
#endif

// safe wrappers to pthread functions
#define fprintf_stderr(fmt, params...)	fprintf(stderr, fmt, ##params)

#define SAFE_PTHREAD_1ARG(a, b, c) { \
	int32_t pter = a(b); \
	if(pter != 0) \
	{ \
		c("FATAL ERROR: %s() failed in %s with error %d %s\n", #a, __func__, pter, strerror(pter)); \
	} }

#define SAFE_MUTEX_LOCK(a)						SAFE_PTHREAD_1ARG(pthread_mutex_lock, a, cs_log)
#define SAFE_MUTEX_UNLOCK(a)					SAFE_PTHREAD_1ARG(pthread_mutex_unlock, a, cs_log)
#define SAFE_COND_SIGNAL(a)						SAFE_PTHREAD_1ARG(pthread_cond_signal, a, cs_log)
#define SAFE_COND_BROADCAST(a)					SAFE_PTHREAD_1ARG(pthread_cond_broadcast, a, cs_log)
#define SAFE_RWLOCK_RDLOCK(a)					SAFE_PTHREAD_1ARG(pthread_rwlock_rdlock, a, cs_log)
#define SAFE_RWLOCK_WRLOCK(a)					SAFE_PTHREAD_1ARG(pthread_rwlock_wrlock, a, cs_log)
#define SAFE_RWLOCK_UNLOCK(a)					SAFE_PTHREAD_1ARG(pthread_rwlock_unlock, a, cs_log)
#define SAFE_ATTR_INIT(a)						SAFE_PTHREAD_1ARG(pthread_attr_init, a, cs_log)
#define SAFE_MUTEXATTR_INIT(a)					SAFE_PTHREAD_1ARG(pthread_mutexattr_init, a, cs_log)
#define SAFE_CONDATTR_INIT(a)					SAFE_PTHREAD_1ARG(pthread_condattr_init, a, cs_log)

#define SAFE_MUTEX_LOCK_NOLOG(a)				SAFE_PTHREAD_1ARG(pthread_mutex_lock, a, fprintf_stderr)
#define SAFE_MUTEX_UNLOCK_NOLOG(a)				SAFE_PTHREAD_1ARG(pthread_mutex_unlock, a, fprintf_stderr)
#define SAFE_COND_SIGNAL_NOLOG(a)				SAFE_PTHREAD_1ARG(pthread_cond_signal, a, fprintf_stderr)
#define SAFE_MUTEX_UNLOCK_NOLOG(a)				SAFE_PTHREAD_1ARG(pthread_mutex_unlock, a, fprintf_stderr)
#define SAFE_ATTR_INIT_NOLOG(a)					SAFE_PTHREAD_1ARG(pthread_attr_init, a, fprintf_stderr)
#define SAFE_CONDATTR_INIT_NOLOG(a)				SAFE_PTHREAD_1ARG(pthread_condattr_init, a, fprintf_stderr)

#define SAFE_PTHREAD_2ARG(a, b, c, d) { \
	int32_t pter = a(b, c); \
	if(pter != 0) \
	{ \
		d("FATAL ERROR: %s() failed in %s with error %d %s\n", #a, __func__, pter, strerror(pter)); \
	} }

#define SAFE_COND_WAIT(a,b)						SAFE_PTHREAD_2ARG(pthread_cond_wait, a, b, cs_log)
#define SAFE_THREAD_JOIN(a,b)					SAFE_PTHREAD_2ARG(pthread_join, a, b, cs_log)
#define SAFE_SETSPECIFIC(a,b)					SAFE_PTHREAD_2ARG(pthread_setspecific, a, b, cs_log)
#define SAFE_MUTEXATTR_SETTYPE(a,b)				SAFE_PTHREAD_2ARG(pthread_mutexattr_settype, a, b, cs_log)
#define SAFE_MUTEX_INIT(a,b)					SAFE_PTHREAD_2ARG(pthread_mutex_init, a, b, cs_log)
#define SAFE_COND_INIT(a,b)						SAFE_PTHREAD_2ARG(pthread_cond_init, a, b, cs_log)
#define SAFE_CONDATTR_SETCLOCK(a,b)				SAFE_PTHREAD_2ARG(pthread_condattr_setclock, a, b, cs_log)

#define SAFE_MUTEX_INIT_NOLOG(a,b)				SAFE_PTHREAD_2ARG(pthread_mutex_init, a, b, fprintf_stderr)
#define SAFE_COND_INIT_NOLOG(a,b)				SAFE_PTHREAD_2ARG(pthread_cond_init, a, b, fprintf_stderr)
#define SAFE_THREAD_JOIN_NOLOG(a,b)				SAFE_PTHREAD_2ARG(pthread_join, a, b, fprintf_stderr)
#define SAFE_CONDATTR_SETCLOCK_NOLOG(a,b)		SAFE_PTHREAD_2ARG(pthread_condattr_setclock, a, b, fprintf_stderr)

#define SAFE_PTHREAD_1ARG_R(a, b, c, d) { \
	int32_t pter = a(b); \
	if(pter != 0) \
	{ \
		c("FATAL ERROR: %s() failed in %s (called from %s) with error %d %s\n", #a, __func__, d, pter, strerror(pter)); \
	} }

#define SAFE_MUTEX_LOCK_R(a, b)					SAFE_PTHREAD_1ARG_R(pthread_mutex_lock, a, cs_log, b)
#define SAFE_MUTEX_UNLOCK_R(a, b)				SAFE_PTHREAD_1ARG_R(pthread_mutex_unlock, a, cs_log, b)
#define SAFE_COND_SIGNAL_R(a, b)				SAFE_PTHREAD_1ARG_R(pthread_cond_signal, a, cs_log, b)
#define SAFE_COND_BROADCAST_R(a, b)				SAFE_PTHREAD_1ARG_R(pthread_cond_broadcast, a, cs_log, b)
#define SAFE_CONDATTR_INIT_R(a, b)				SAFE_PTHREAD_1ARG_R(pthread_condattr_init, a, cs_log, b)

#define SAFE_MUTEX_LOCK_NOLOG_R(a, b)			SAFE_PTHREAD_1ARG_R(pthread_mutex_lock, a, fprintf_stderr, b)
#define SAFE_MUTEX_UNLOCK_NOLOG_R(a, b)			SAFE_PTHREAD_1ARG_R(pthread_mutex_unlock, a, fprintf_stderr, b)
#define SAFE_CONDATTR_INIT_NOLOG_R(a, b)		SAFE_PTHREAD_1ARG_R(pthread_condattr_init, a, fprintf_stderr, b)

#define SAFE_PTHREAD_2ARG_R(a, b, c, d, e) { \
	int32_t pter = a(b, c); \
	if(pter != 0) \
	{ \
		d("FATAL ERROR: %s() failed in %s (called from %s) with error %d %s\n", #a, __func__, e, pter, strerror(pter)); \
	} }

#define SAFE_MUTEX_INIT_R(a,b,c)				SAFE_PTHREAD_2ARG_R(pthread_mutex_init, a, b, cs_log, c)
#define SAFE_COND_INIT_R(a,b,c)					SAFE_PTHREAD_2ARG_R(pthread_cond_init, a, b, cs_log, c)
#define SAFE_CONDATTR_SETCLOCK_R(a,b,c)			SAFE_PTHREAD_2ARG(pthread_condattr_setclock, a, b, cs_log, c)

#define SAFE_MUTEX_INIT_NOLOG_R(a,b,c)			SAFE_PTHREAD_2ARG_R(pthread_mutex_init, a, b, fprintf_stderr, c)
#define SAFE_COND_INIT_NOLOG_R(a,b,c)			SAFE_PTHREAD_2ARG_R(pthread_cond_init, a, b, fprintf_stderr, c)
#define SAFE_CONDATTR_SETCLOCK_NOLOG_R(a,b,c)	SAFE_PTHREAD_2ARG(pthread_condattr_setclock, a, b, fprintf_stderr, c)

#define SAFE_COND_TIMEDWAIT(a, b, c) { \
	int32_t pter; \
	if((c)->tv_nsec < 0) (c)->tv_nsec = 0; \
	if((c)->tv_nsec > 999999999) (c)->tv_nsec = 999999999; \
	pter = pthread_cond_timedwait(a, b, c); \
	if(pter != 0 && pter != ETIMEDOUT) \
	{ \
		cs_log("FATAL ERROR: pthread_cond_timedwait failed in %s with error %d %s\n", __func__, pter, strerror(pter)); \
	} }

#define SAFE_COND_TIMEDWAIT_R(a, b, c, d) { \
	int32_t pter; \
	if((c)->tv_nsec < 0) (c)->tv_nsec = 0; \
	if((c)->tv_nsec > 999999999) (c)->tv_nsec = 999999999; \
	pter = pthread_cond_timedwait(a, b, c); \
	if(pter != 0 && pter != ETIMEDOUT) \
	{ \
		cs_log("FATAL ERROR: pthread_cond_timedwait failed in %s (called from %s) with error %d %s\n", __func__, d, pter, strerror(pter)); \
	} }

#define SAFE_ATTR_SETSTACKSIZE(a,b) { \
	int32_t pter = pthread_attr_setstacksize(a, b); \
	if(pter != 0) \
	{ \
		cs_log("WARNING: pthread_attr_setstacksize() failed in %s with error %d %s\n", __func__, pter, strerror(pter)); \
	} }

#define SAFE_ATTR_SETSTACKSIZE_NOLOG(a,b) { \
	int32_t pter = pthread_attr_setstacksize(a, b); \
	if(pter != 0) \
	{ \
		fprintf_stderr("WARNING: pthread_attr_setstacksize() failed in %s with error %d %s\n", __func__, pter, strerror(pter)); \
	} }

#ifdef NO_PTHREAD_STACKSIZE
#undef SAFE_ATTR_SETSTACKSIZE
#undef SAFE_ATTR_SETSTACKSIZE_NOLOG
#define SAFE_ATTR_SETSTACKSIZE(a,b)
#define SAFE_ATTR_SETSTACKSIZE_NOLOG(a,b)
#endif

#define CHECK_BIT(var,pos) (((var) & (1<<(pos)))? 1 : 0)

/* ===========================
 *			constants
 * =========================== */
#define CS_VERSION				"1.20_svn"
#ifndef CS_SVN_VERSION
# define CS_SVN_VERSION			"test"
#endif
#ifdef CS_CACHEEX
#ifdef CS_CACHEEX_AIO
#define CS_AIO_VERSION			CS_SVN_VERSION
#endif
#endif
#ifndef CS_TARGET
# define CS_TARGET				"unknown"
#endif
#ifndef CS_CONFDIR
#define CS_CONFDIR				"/usr/local/etc"
#endif
#ifndef CS_LOGFILE
#define CS_LOGFILE				"/var/log/oscam.log"
#endif
#define CS_QLEN					128		// size of request queue
#define CS_MAXPROV				32
#define CS_MAXPORTS				32		// max server ports
#define CS_CLIENT_HASHBUCKETS	32
#define CS_SERVICENAME_SIZE		32

#define CS_ECMSTORESIZE			16		// use MD5()
#define CS_EMMSTORESIZE			16		// use MD5()
#define CS_CLIENT_TIMEOUT		5000
#define CS_CLIENT_MAXIDLE		120
#define CS_BIND_TIMEOUT			120
#define CS_DELAY				0
#define CS_ECM_RINGBUFFER_MAX	0x10	// max size for ECM last responsetimes ringbuffer. Keep this set to power of 2 values!

// Support for multiple CWs per channel and other encryption algos
#define WITH_EXTENDED_CW		1

#if defined(READER_DRE) || defined(READER_DRECAS) || defined(READER_VIACCESS) || defined(WITH_EMU)
#define MAX_ECM_SIZE			1024
#define MAX_EMM_SIZE			1024
#else
#define MAX_ECM_SIZE			596
#define MAX_EMM_SIZE			512
#endif

#ifdef WITH_EMU
#define CS_EMMCACHESIZE			1024	// nr of EMMs that EMU reader will cache
#else
#define CS_EMMCACHESIZE			512		// nr of EMMs that each reader will cache
#endif
#define MSGLOGSIZE				64		// size of string buffer for a ecm to return messages

#define D_TRACE					0x0001	// Generate very detailed error/trace messages per routine
#define D_ATR					0x0002	// Debug ATR parsing, dump of ecm, cw
#define D_READER				0x0004	// Debug Reader/Proxy Process
#define D_CLIENT				0x0008	// Debug Client Process
#define D_IFD					0x0010	// Debug IFD+protocol
#define D_DEVICE				0x0020	// Debug Reader I/O
#define D_EMM					0x0040	// Dumps EMM
#define D_DVBAPI				0x0080	// Debug DVBAPI
#define D_LB					0x0100	// Debug Loadbalancer/ECM handler
#define D_CACHEEX				0x0200	// Debug CACHEEX
#define D_CLIENTECM				0x0400	// Debug Client ECMs
#define D_CSP					0x0800	// Debug CSP
#define D_CWC					0x1000	// Debug CWC
#ifdef CS_CACHEEX_AIO
#define D_CW_CACHE				0x2000	// Debug CW Cache
#endif
#define D_ALL_DUMP				0xFFFF	// dumps all

#ifdef CS_CACHEEX_AIO
#define MAX_DEBUG_LEVELS		14
#else
#define MAX_DEBUG_LEVELS		13
#endif

/////// phoenix readers which need baudrate setting and timings need to be guarded by OSCam: BEFORE R_MOUSE
#define R_DB2COM1				0x1		// Reader Dbox2 @ com1
#define R_DB2COM2				0x2		// Reader Dbox2 @ com1
#define R_SC8in1				0x3		// Reader Sc8in1 or MCR
#define R_MP35					0x4		// AD-Teknik Multiprogrammer 3.5 and 3.6 (only usb tested)
#define R_MOUSE					0x5		// Reader smartcard mouse
/////// internal readers (Dreambox, Coolstream, IPBox) are all R_INTERNAL, they are determined compile-time
#define R_INTERNAL				0x6		// Reader smartcard intern
/////// readers that do not reed baudrate setting and timings are guarded by reader itself (large buffer built in): AFTER R_SMART
#define R_SMART					0x7		// Smartreader+
#define R_PCSC					0x8		// PCSC
#define R_DRECAS				0x9		// Reader DRECAS
#define R_EMU					0x17	// Reader EMU
/////// proxy readers after R_CS378X
#define R_CAMD35				0x20	// Reader cascading camd 3.5x
#define R_CAMD33				0x21	// Reader cascading camd 3.3x
#define R_NEWCAMD				0x22	// Reader cascading newcamd
#define R_RADEGAST				0x23	// Reader cascading radegast
#define R_CS378X				0x24	// Reader cascading camd 3.5x TCP
#define R_CONSTCW				0x25	// Reader for Constant CW
#define R_CSP					0x26	// Cache CSP
#define R_GHTTP					0x27	// Reader ghttp
#define R_SCAM					0x28	// Reader cascading scam
/////// peer to peer proxy readers after R_CCCAM
#define R_GBOX					0x30	// Reader cascading gbox
#define R_CCCAM					0x35	// Reader cascading cccam
#define R_PANDORA				0x36	// Reader cascading pandora
#define R_SERIAL				0x80	// Reader serial
#define R_IS_NETWORK			0x60
#define R_IS_CASCADING			0xE0

#define is_network_reader(__X) (__X->typ & R_IS_NETWORK)
#define is_cascading_reader(__X) (__X->typ & R_IS_CASCADING)
#define is_smargo_reader(__X) (__X->crdr && strcmp(__X->crdr->desc, "smargo") == 0)

// ECM rc codes:
/////// all found
#define E_FOUND					0
#define E_CACHE1				1
#define E_CACHE2				2
#define E_CACHEEX				3
/////// all notfound, some error or problem
#define E_NOTFOUND				4		// for selection of found, use < E_NOTFOUND
#define E_TIMEOUT				5
#define E_SLEEPING				6
#define E_FAKE					7
#define E_INVALID				8
#define E_CORRUPT				9
#define E_NOCARD				10
#define E_EXPDATE				11
#define E_DISABLED				12
#define E_STOPPED				13		// for selection of error, use <= E_STOPPED and exclude selection of found

#define E_ALREADY_SENT			101
#define E_WAITING				102
#define E_99					99		// this code is undocumented
#define E_UNHANDLED				100		// for selection of unhandled, use >= E_UNHANDLED

#define CS_MAX_MOD				20
#define MOD_CONN_TCP			1
#define MOD_CONN_UDP			2
#define MOD_CONN_NET			3
#define MOD_CONN_SERIAL			4
#define MOD_NO_CONN				8

#define EMM_UNIQUE				1
#define EMM_SHARED				2
#define EMM_GLOBAL				4
#define EMM_UNKNOWN				8

// Listener Types
#define LIS_CAMD33TCP			1
#define LIS_CAMD35UDP			2
#define LIS_CAMD35TCP			4
#define LIS_NEWCAMD				8
#define LIS_CCCAM				16
#define LIS_GBOX				32
#define LIS_RADEGAST			64
#define LIS_DVBAPI				128
#define LIS_CONSTCW				256
#define LIS_SERIAL				1024
#define LIS_CSPUDP				2048
#define LIS_SCAM				4096

// EMM types:
#define UNKNOWN					0
#define UNIQUE					1
#define SHARED					2
#define GLOBAL					3

#define NCD_AUTO				0
#define NCD_524					1
#define NCD_525					2

// moved from reader-common.h
#define UNKNOWN					0
#define CARD_NEED_INIT			1
#define CARD_INSERTED			2
#define CARD_FAILURE			3
#define NO_CARD					4
#define READER_DEVICE_ERROR		5

// moved from stats
#define DEFAULT_REOPEN_SECONDS					30
#define DEFAULT_MIN_ECM_COUNT					5
#define DEFAULT_MAX_ECM_COUNT					500
#define DEFAULT_NBEST							1
#define DEFAULT_NFB								1
#define DEFAULT_RETRYLIMIT						0
#define DEFAULT_LB_MODE							0
#define DEFAULT_LB_STAT_CLEANUP					336
#define DEFAULT_UPDATEINTERVAL					240
#define DEFAULT_LB_AUTO_BETATUNNEL				1
#define DEFAULT_LB_AUTO_BETATUNNEL_MODE			0
#define DEFAULT_LB_AUTO_BETATUNNEL_PREFER_BETA	50

#define DEFAULT_MAX_CACHE_TIME					15
#define DEFAULT_MAX_HITCACHE_TIME				15

#define DEFAULT_LB_AUTO_TIMEOUT					0
#define DEFAULT_LB_AUTO_TIMEOUT_P				30
#define DEFAULT_LB_AUTO_TIMEOUT_T				300

enum {E1_GLOBAL = 0, E1_USER, E1_READER, E1_SERVER, E1_LSERVER};

// LB blocking events:
enum {E2_GLOBAL = 0, E2_GROUP, E2_CAID, E2_IDENT, E2_CLASS, E2_CHID, E2_QUEUE, E2_OFFLINE,
	  E2_SID, E2_CCCAM_NOCARD,
	  // From here only LB nonblocking events:
	  E2_CCCAM_NOK1, E2_CCCAM_NOK2, E2_CCCAM_LOOP, E2_WRONG_CHKSUM, E2_RATELIMIT
	 };

#define LB_NONBLOCK_E2_FIRST E2_CCCAM_NOK1

#define CTA_RES_LEN				512

#define MAX_ATR_LEN				33		// max. ATR length
#define MAX_HIST				15		// max. number of historical characters

#define MAX_SIDBITS				64		// max services
#define SIDTABBITS				uint64_t // 64bit type for services, if a system does not support this type,
// please use a define and define it as uint32_t / MAX_SIDBITS 32

#define BAN_UNKNOWN				1		// Failban mask for anonymous/ unknown contact
#define BAN_DISABLED			2		// Failban mask for Disabled user
#define BAN_SLEEPING			4		// Failban mask for sleeping user
#define BAN_DUPLICATE			8		// Failban mask for duplicate user

#define MAX_HTTP_DYNDNS			3		// maximum allowed Dyndns addresses for webif access

#define CHECK_WAKEUP			1
#define CHECK_ANTICASCADER		2
#define CHECK_ECMCACHE			3

#define AVAIL_CHECK_CONNECTED	0
#define AVAIL_CHECK_LOADBALANCE	1

#define ECM_FMT_LEN				109		// 64
#define CXM_FMT_LEN				209		// 160

#define LB_MAX_STAT_TIME		10

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#define OSCAM_SIGNAL_WAKEUP		SIGCONT
#else
#define OSCAM_SIGNAL_WAKEUP		SIGRTMAX-2
#endif

#define READER_ACTIVE			0x01
#define READER_FALLBACK			0x02
#define READER_LOCAL			0x04
#define READER_CACHEEX			0x08

#define REQUEST_SENT			0x10
#define REQUEST_ANSWERED		0x20

#define CW_MODE_ONE_CW			0
#define CW_MODE_MULTIPLE_CW		1
#define CW_TYPE_VIDEO			0
#define CW_TYPE_AUDIO			1
#define CW_TYPE_DATA			2
#define CW_ALGO_CSA				0
#define CW_ALGO_DES				1
#define CW_ALGO_AES128			2
#define CW_ALGO_MODE_ECB		0
#define CW_ALGO_MODE_CBC		1

#define SIZE_SHORTDAY			8
#define MAXALLOWEDTF			1001	// 10 allowed time frame slots for everyday + all [(3 + 1 + 10*(12) + 1)*8]
extern const char *shortDay[SIZE_SHORTDAY];
extern const char *weekdstr;

/* ===========================
 *		Default Values
 * =========================== */
#define DEFAULT_INACTIVITYTIMEOUT 0
#define DEFAULT_TCP_RECONNECT_TIMEOUT 30
#define DEFAULT_NCD_KEEPALIVE	0

#define DEFAULT_CC_MAXHOPS		10
#define DEFAULT_CC_RESHARE		-1		// Use global cfg
#define DEFAULT_CC_IGNRSHR		-1		// Use global cfg
#define DEFAULT_CC_STEALTH		-1		// Use global cfg
#define DEFAULT_CC_KEEPALIVE	0
#define DEFAULT_CC_RECONNECT	12000
#define DEFAULT_CC_RECV_TIMEOUT	2000

#define DEFAULT_AC_USERS		-1		// Use global cfg
#define DEFAULT_AC_PENALTY		-1		// Use global cfg

// Return MPEG section length
#define SCT_LEN(sct) (3+((sct[1]&0x0f)<<8)+sct[2])
// Used by readers
#define MAX_LEN					256

#define NO_CAID_VALUE			0xfffe
#define NO_PROVID_VALUE			0xfffffe
#define NO_SRVID_VALUE			0xfffe

// If NULL return empty string
#define ESTR(x) ((x) ? (x) : "")

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

/*
  See: http://stackoverflow.com/questions/10269685/kernels-container-of-any-way-to-make-it-iso-conforming
       http://www.kroah.com/log/linux/container_of.html
*/
#define container_of(ptr, type, member) \
	((type *) ((char *) (ptr) - offsetof(type, member) + \
		(&((type *) 0)->member == (ptr)) * 0))

/* ===========================
 *		global structures
 * =========================== */
struct timeb
{
	time_t			time;
	int64_t			millitm;
};

typedef struct cs_mutexlock
{
	int32_t			timeout;
	pthread_mutex_t	lock;
	pthread_cond_t	writecond, readcond;
	const char		*name;
	int8_t			flag;
	int16_t			writelock, readlock;
} CS_MUTEX_LOCK;

#include "oscam-llist.h"

typedef struct s_caidvaluetab_data
{
	uint16_t		caid;
	uint16_t		value;
} CAIDVALUETAB_DATA;

typedef struct s_caidvaluetab
{
	int32_t			cvnum;
	CAIDVALUETAB_DATA *cvdata;
} CAIDVALUETAB;

typedef struct s_classtab
{
	uint8_t			an;
	uint8_t			bn;
	uint8_t			*aclass;
	uint8_t			*bclass;
} CLASSTAB;

typedef struct s_caidtab_data
{
	uint16_t		caid;
	uint16_t		mask;
	uint16_t		cmap;
} CAIDTAB_DATA;

typedef struct s_caidtab
{
	int32_t			ctnum;
	CAIDTAB_DATA	*ctdata;
} CAIDTAB;

typedef struct s_tuntab_data
{
	uint16_t		bt_caidfrom;
	uint16_t		bt_caidto;
	uint16_t		bt_srvid;
} TUNTAB_DATA;

typedef struct s_tuntab
{
	int32_t			ttnum;
	TUNTAB_DATA		*ttdata;
} TUNTAB;

typedef struct s_sidtab
{
	char			label[64];
#ifdef CS_CACHEEX_AIO
	uint8_t			disablecrccws_only_for_exception;
	uint8_t			no_wait_time;
	uint8_t			lg_only_exception;
#endif
	uint16_t		num_caid;
	uint16_t		num_provid;
	uint16_t		num_srvid;
	uint16_t		*caid;
	uint32_t		*provid;
	uint16_t		*srvid;
	struct s_sidtab	*next;
} SIDTAB;

typedef struct s_filter
{
	uint16_t		caid;
	uint8_t			nprids;
	uint32_t		prids[CS_MAXPROV];
} FILTER;

typedef struct s_ftab
{
	int32_t			nfilts;
	FILTER			*filts;
} FTAB;

typedef struct s_ncd_ftab
{
	int32_t			nfilts;
	FILTER			filts[16];
} NCD_FTAB;

struct ncd_port
{
	bool			ncd_key_is_set;
	uint8_t			ncd_key[14];
	NCD_FTAB		ncd_ftab;
};

typedef struct s_port
{
	int32_t			fd;
	int32_t			s_port;
	struct ncd_port	*ncd;							// newcamd specific settings
} PORT;

typedef struct s_ptab
{
	int32_t			nports;
	PORT			ports[CS_MAXPORTS];
} PTAB;

typedef struct aes_entry
{
	uint16_t		keyid;
	uint16_t		caid;
	uint32_t		ident;
	uint8_t			plainkey[16];
	AES_KEY			key;
	struct aes_entry *next;
} AES_ENTRY;

struct aes_keys
{
	AES_KEY			aeskey_encrypt;					// encryption key needed by monitor and used by camd33, camd35
	AES_KEY			aeskey_decrypt;					// decryption key needed by monitor and used by camd33, camd35
};

struct s_ecm
{
	uint8_t			ecmd5[CS_ECMSTORESIZE];
	uint8_t			cw[16];
	uint16_t		caid;
	uint64_t		grp;
	struct s_reader	*reader;
	int32_t			rc;
	time_t			time;
};

struct s_emmstat
{
	uint8_t			emmd5[CS_EMMSTORESIZE];
	uint8_t			type;
	int32_t			count;
	struct timeb	firstwritten;
	struct timeb	lastwritten;
};

struct s_emmcache
{
	uint8_t			emmd5[CS_EMMSTORESIZE];
	uint8_t			type;
	uint16_t		len;
	uint8_t			emm[MAX_EMM_SIZE];
	struct timeb	firstseen;
	struct timeb	lastseen;
};

struct s_csystem_emm_filter
{
	uint8_t			type;
	uint8_t			enabled;
	uint8_t			filter[16];
	uint8_t			mask[16];
};

typedef struct v_ban								// Failban listmember
{
	int32_t			v_count;
	IN_ADDR_T		v_ip;
	int32_t			v_port;
	struct timeb	v_time;
	bool			acosc_entry;
	int32_t			acosc_penalty_dur;
	char			*info;
} V_BAN;

typedef struct s_cacheex_stat_entry					// Cacheex stats listmember
{
	int32_t			cache_count;
	time_t			cache_last;
	uint16_t		cache_caid;
	uint16_t		cache_srvid;
	uint32_t		cache_prid;
	int8_t			cache_direction;				// 0 = push / 1 = got
#ifdef CS_CACHEEX_AIO
	int32_t			cache_count_lg;
#endif
} S_CACHEEX_STAT_ENTRY;

typedef struct s_entitlement						// contains entitlement Info
{
	uint64_t		id;								// the element ID
	uint32_t		type;							// enumerator for tier,chid whatever
													// 0="", 1="Package", 2="PPV-Event", 3="chid", 4="tier", 5 = "class", 6 = "PBM". 7 = "seca-admin"
	uint16_t		caid;							// the caid of element
	uint32_t		provid;							// the provid of element
	uint32_t		class;							// the class needed for some systems
	time_t			start;							// startdate
	time_t			end;							// enddate
#ifdef WITH_EMU
	bool			isKey;
	bool			isData;
	char			name[8];
	uint8_t			*key;
	uint32_t		keyLength;
#endif
} S_ENTITLEMENT;

struct s_client;
struct ecm_request_t;
struct emm_packet_t;
struct s_ecm_answer;
struct demux_s;

#define DEFAULT_MODULE_BUFSIZE 1024

struct s_module
{
	const char		*desc;
	int8_t			type;
	int8_t			large_ecm_support;
	int16_t			listenertype;
	//int32_t		s_port;
	IN_ADDR_T		s_ip;
	uint16_t		bufsize;
	void			*(*s_handler)(struct s_client *, uint8_t *, int32_t);
	void			(*s_init)(struct s_client *);
	int32_t			(*recv)(struct s_client *, uint8_t *, int32_t);
	void			(*send_dcw)(struct s_client *, struct ecm_request_t *);
	void			(*cleanup)(struct s_client *);
	int32_t			(*c_recv_chk)(struct s_client *, uint8_t *, int32_t *, uint8_t *, int32_t);
	int32_t			(*c_init)(struct s_client *);
	int32_t			(*c_send_ecm)(struct s_client *, struct ecm_request_t *);
	int32_t			(*c_send_emm)(struct emm_packet_t *);
	int32_t			(*c_available)(struct s_reader *, int32_t, struct ecm_request_t *); // Schlocke: available check for load-balancing,
	// params:
	// rdr (reader to check)
	// int32_t			checktype (0=return connected, 1=return loadbalance-avail) return int
	void			(*c_idle)(void); // Schlocke: called when reader is idle
	void			(*s_idle)(struct s_client *);
	void			(*s_peer_idle)(struct s_client *);
	void			(*c_card_info)(void); // Schlocke: request card infos

	int32_t			(*c_capmt)(struct s_client *, struct demux_s *);

#ifdef CS_CACHEEX
	int32_t			(*c_cache_push)(struct s_client *, struct ecm_request_t *); // Cache push
	int32_t			(*c_cache_push_chk)(struct s_client *, struct ecm_request_t *); // Cache push Node Check, 0=no push
#endif
	int32_t			c_port;
	PTAB			ptab;
	int32_t			num;
};

struct s_ATR;

struct s_cardreader_settings
{
	uint32_t		ETU;
	uint32_t		EGT;
	uint8_t			P;
	uint32_t		I;
	uint32_t		F;
	uint32_t		Fi;
	uint8_t			Di;
	uint8_t			Ni;
	uint32_t		WWT;
	uint32_t		BGT;
	uint8_t			D;
};

struct s_cardreader
{
	const char		*desc;
	int32_t			(*reader_init)(struct s_reader *);
	int32_t			(*get_status)(struct s_reader *, int *);
	int32_t			(*activate)(struct s_reader *, struct s_ATR *);
	int32_t			(*transmit)(struct s_reader *, uint8_t *sent, uint32_t size, uint32_t expectedlen, uint32_t delay, uint32_t timeout);
	int32_t			(*receive)(struct s_reader *, uint8_t *data, uint32_t size, uint32_t delay, uint32_t timeout);
	int32_t			(*lock_init)(struct s_reader *);
	void			(*lock)(struct s_reader *);
	void			(*unlock)(struct s_reader *);
	int32_t			(*close)(struct s_reader *);
	int32_t			(*set_parity)(struct s_reader *, uint8_t parity);
	int32_t			(*write_settings)(struct s_reader *, struct s_cardreader_settings *s);
	int32_t			(*set_protocol)(struct s_reader *, uint8_t *params, uint32_t *length, uint32_t len_request);
	int32_t			(*set_baudrate)(struct s_reader *, uint32_t baud); // set only for readers which need baudrate setting and timings need to be guarded by OSCam
	int32_t			(*card_write)(struct s_reader *pcsc_reader, const uint8_t *buf, uint8_t *cta_res, uint16_t *cta_lr, int32_t l);
	void			(*display_msg)(struct s_reader *, char *msg);

	int32_t			(*do_reset)(struct s_reader *, struct s_ATR *, int32_t (*rdr_activate_card)(struct s_reader *, struct s_ATR *, uint16_t deprecated), int32_t (*rdr_get_cardsystem)(struct s_reader *, struct s_ATR *));

	bool			(*set_DTS_RTS)(struct s_reader *, int32_t *dtr, int32_t *rts);

	int32_t			typ;							// fixme: workaround, remove when all old code is converted

	int8_t			max_clock_speed;				// 1 for reader->typ > R_MOUSE
	int8_t			need_inverse;					// 0 = reader does inversing; 1 = inversing done by oscam
	//io_serial config
	int8_t			flush;
	int8_t			read_written;					// 1 = written bytes has to read from device
	bool			skip_extra_atr_parsing;
	bool			skip_t1_command_retries;
	bool			skip_setting_ifsc;
};

struct s_cardsystem
{
	const char		*desc;
	const uint16_t	*caids;
	int32_t			(*card_init)(struct s_reader *reader, struct s_ATR *);
	void			(*card_done)(struct s_reader *reader);
	int32_t			(*card_info)(struct s_reader *);
	void			(*poll_status)(struct s_reader *);
	int32_t			(*do_ecm)(struct s_reader *, const struct ecm_request_t *, struct s_ecm_answer *);
	int32_t			(*do_emm_reassembly)(struct s_reader *, struct s_client *, struct emm_packet_t *); // Returns 1/true if the EMM is ready to be written in the card
	int32_t			(*do_emm)(struct s_reader *, struct emm_packet_t *);
	void			(*post_process)(struct s_reader *);
	int32_t			(*get_emm_type)(struct emm_packet_t *, struct s_reader *);
	int32_t			(*get_emm_filter)(struct s_reader *, struct s_csystem_emm_filter **, uint32_t *);
	int32_t			(*get_emm_filter_adv)(struct s_reader *, struct s_csystem_emm_filter **, uint32_t *, uint16_t, uint32_t, uint16_t, uint16_t, uint16_t, uint32_t);
	int32_t			(*get_tunemm_filter)(struct s_reader *, struct s_csystem_emm_filter **, uint32_t *);
};

typedef struct cw_extendted_t
{
#ifdef WITH_EXTENDED_CW
	uint8_t			mode;
	uint8_t			audio[4][16];					// 4 x odd/even pairs of 8 byte CWs
	uint8_t			data[16];						// odd/even pair of 8 byte CW or 16 byte IV
	uint8_t			session_word[32];				// odd/even pair of 16 byte CW
	uint8_t			algo;							// CSA, DES or AES128
	uint8_t			algo_mode;						// ECB or CBC
#else
	uint8_t			disabled;
#endif
} EXTENDED_CW;

typedef struct ecm_request_t
{
	uint8_t			ecm[MAX_ECM_SIZE];
	uint8_t			cw[16];
	EXTENDED_CW		cw_ex;
	uint8_t			ecmd5[CS_ECMSTORESIZE];
	int16_t			ecmlen;
	uint16_t		caid;
	uint16_t		ocaid;							// original caid, used for betatunneling
	uint16_t		srvid;
	uint16_t		onid;
	uint16_t		tsid;
	uint16_t		pmtpid;
	uint32_t		ens;							// enigma namespace
	uint32_t		vpid;							// videopid
	uint16_t		chid;
	uint16_t		pid;
	uint16_t		idx;
	uint32_t		prid;
	struct s_reader	*selected_reader;
	struct s_ecm_answer *matching_rdr;				// list of matching readers
	const struct s_reader *fallback;				// fallback is the first fallback reader in the list matching_rdr
	struct s_client	*client;						// contains pointer to 'c' client while running in 'r' client
	uint64_t		grp;
	int32_t			msgid;							// client pending table index
	uint8_t			stage;							// processing stage in server module
	int8_t			rc;
	uint8_t			rcEx;
	struct timeb	tps;							// incoming time stamp
	int8_t			btun;							// mark er as betatunneled
	uint16_t		reader_avail;					// count of available readers for ecm
	uint16_t		readers;						// count of available used readers for ecm
	uint16_t		reader_requested;				// count of real requested readers
	uint16_t		localreader_count;				// count of selected local readers
	uint16_t		cacheex_reader_count;			// count of selected cacheex mode-1 readers
	uint16_t		fallback_reader_count;			// count of selected fb readers
	uint16_t		reader_count;					// count of selected not fb readers
	int8_t			preferlocalcards;
	int8_t			checked;						// for doublecheck
	uint8_t			cw_checked[16];					// for doublecheck
	int8_t			readers_timeout_check;			// set to 1 after ctimeout occurs and readers not answered are checked
	struct s_reader	*origin_reader;

#if defined MODULE_CCCAM
	void			*origin_card;					// CCcam preferred card!
#endif

#if defined MODULE_GBOX
	uint32_t		gbox_crc;						// rcrc for gbox, used to identify ECM task in peer responses
	uint16_t		gbox_cw_src_peer;
	uint16_t		gbox_ecm_src_peer;
	uint8_t			gbox_ecm_dist;
	uint8_t			gbox_ecm_status;
	LLIST			*gbox_cards_pending;			// type gbox_card_pending
#endif

	void			*src_data;
	uint32_t		csp_hash;						// csp has its own hash

	struct s_client	*cacheex_src;					// Cacheex origin
#ifdef CS_CACHEEX
	int8_t			cacheex_pushed;					// to avoid duplicate pushs
	uint8_t			csp_answered;					// =1 if er get answer by csp
	LLIST			*csp_lastnodes;					// last 10 Cacheex nodes atm cc-proto-only
	uint32_t		cacheex_wait_time;				// cacheex wait time in ms
	uint8_t			cacheex_wait_time_expired;		// =1 if cacheex wait_time expires
	uint16_t		cacheex_mode1_delay;			// cacheex mode 1 delay
	uint8_t			cacheex_hitcache;				// =1 if wait_time due hitcache
	void			*cw_cache;						// pointer to cw stored in cache
#endif
#ifdef CS_CACHEEX_AIO
	int32_t			ecm_time;						// ecm-time in ms
	uint8_t			localgenerated;					// flag for local generated CW
#endif
	uint32_t		cw_count;
	uint8_t			from_csp;						// =1 if er from csp cache
	uint8_t			from_cacheex;					// =1 if er from cacheex client pushing cache
	uint8_t			from_cacheex1_client;			// =1 if er from cacheex-1 client
	char			msglog[MSGLOGSIZE];
	uint8_t			cwc_cycletime;
	uint8_t			cwc_next_cw_cycle;
#ifdef CW_CYCLE_CHECK
	char			cwc_msg_log[MSGLOGSIZE];
#endif
#ifdef WITH_STAPI5
	char			dev_name[20];
#endif
	struct ecm_request_t *parent;
	struct ecm_request_t *next;
#ifdef HAVE_DVBAPI
	uint8_t			adapter_index;
#endif
} ECM_REQUEST;


struct s_ecm_answer
{
	uint8_t			status;
	struct s_reader	*reader;
	ECM_REQUEST		*er;
	int8_t			rc;
	uint8_t			rcEx;
	uint8_t			cw[16];
	EXTENDED_CW		cw_ex;
	char			msglog[MSGLOGSIZE];
	struct timeb	time_request_sent;				// using for evaluate ecm_time
	int32_t			ecm_time;
	uint16_t		tier;							// only filled by local videoguard reader atm
#ifdef WITH_LB
	int32_t			value;
	int32_t			time;
#endif
	struct s_ecm_answer *next;
	CS_MUTEX_LOCK	ecmanswer_lock;
	struct s_ecm_answer *pending;
	struct s_ecm_answer *pending_next;
	bool is_pending;
};

struct s_acasc_shm
{
	uint16_t		ac_count : 15;
	uint16_t		ac_deny  : 1;
};

struct s_acasc
{
	uint16_t		stat[10];
	uint8_t			idx;							// current active index in stat[]
};

struct s_cwresponse
{
	int32_t			duration;
	time_t			timestamp;
	int32_t			rc;
};

struct s_cascadeuser
{
	uint16_t		caid;
	uint32_t		prid;
	uint16_t		srvid;
	time_t			time;
	int8_t			cwrate;
};

typedef struct sidtabs
{
	SIDTABBITS		ok;								// positive services
	SIDTABBITS		no;								// negative services
} SIDTABS;

struct s_zap_list
{
	uint16_t		caid;
	uint32_t		provid;
	uint16_t		chid;
	uint16_t		sid;
	int8_t			request_stage;
	time_t			lasttime;
};

// EMM reassemply
struct emm_rass
{
	int16_t			emmlen;
	int32_t			provid;
	uint8_t			emm[MAX_EMM_SIZE];
};

struct s_client
{
	uint32_t		tid;
	int8_t			init_done;
	pthread_mutex_t	thread_lock;
	int8_t			thread_active;
	int8_t			kill;
	int8_t			kill_started;
	LLIST			*joblist;
	IN_ADDR_T		ip;
	in_port_t		port;
	time_t			login;							// connection
	time_t			logout;							// disconnection
	time_t			last;
	time_t			lastswitch;
	time_t			lastemm;
	time_t			lastecm;
	time_t			expirationdate;
	uint32_t		allowedtimeframe[SIZE_SHORTDAY][24][2]; // day[0-sun to 6-sat, 7-ALL],hours,minutes use as binary flags to reduce mem usage
	uint8_t			allowedtimeframe_set;			// flag for internal use to mention if allowed time frame is used
	int8_t			c35_suppresscmd08;
	uint8_t			c35_sleepsend;
	int8_t			ncd_keepalive;
	int8_t			disabled;
	uint64_t		grp;
	int8_t			crypted;
	int8_t			dup;
	LLIST			*aureader_list;
	int8_t			autoau;
	LLIST			*ra_buf;						// EMM reassembly buffer for viaccess
	struct emm_rass	*cw_rass;						// EMM reassembly buffer for cryptoworks
	int8_t			monlvl;
	CAIDTAB			ctab;
	TUNTAB			ttab;
	SIDTABS			sidtabs;
	SIDTABS			lb_sidtabs;
	int8_t			typ;							// first s_client is type s=starting (master) thread; type r = physical reader, type p = proxy reader both always have 1 s_reader struct allocated; type c = client (user logging in into oscam) type m = monitor type h = http server a = anticascader
	uint8_t			module_idx;
	uint16_t		last_srvid;
	uint32_t		last_provid;
	uint16_t		last_caid;
	struct s_provid	*last_providptr;
	struct s_srvid	*last_srvidptr;
	uint32_t		last_srvidptr_search_provid;
	int32_t			tosleep;
	struct s_auth	*account;
	int32_t			udp_fd;
	struct SOCKADDR	udp_sa;
	socklen_t		udp_sa_len;
	int8_t			tcp_nodelay;
	int8_t			log;
	int32_t			logcounter;
	int32_t			cwfound;						// count found ECMs per client
	int32_t			cwcache;						// count ECMs from cache1/2 per client
	int32_t			cwnot;							// count not found ECMs per client
	int32_t			cwtun;							// count betatunneled ECMs per client
	int32_t			cwignored;						// count ignored ECMs per client
	int32_t			cwtout;							// count timeouted ECMs per client
	int32_t			cwlastresptime;					// last Responsetime (ms)
#ifdef CW_CYCLE_CHECK
	int32_t			cwcycledchecked;				// count checked cwcycles per client
	int32_t			cwcycledok;						// count pos checked cwcycles per client
	int32_t			cwcyclednok;					// count neg checked cwcycles per client
	int32_t			cwcycledign;					// count ign cwcycles per client
#endif
	int32_t			emmok;							// count EMM ok
	int32_t			emmnok;							// count EMM nok
	int8_t			pending;						// number of ECMs pending
#ifdef CS_CACHEEX
	int32_t			cwcacheexpush;					// count pushed ecms/cws
	int32_t			cwcacheexgot;					// count got ecms/cws
	int32_t			cwcacheexhit;					// count hit ecms/cws
	LLIST			*ll_cacheex_stats;				// list for Cacheex statistics
	int8_t			cacheex_maxhop;
	int32_t			cwcacheexerr;					// cw=00 or chksum wrong
	int32_t			cwcacheexerrcw;					// same Hex, different CW
	int16_t			cwcacheexping;					// peer ping in ms, only used by csp
	int32_t			cwc_info;						// count of in/out comming cacheex ecms with CWCinfo
#ifdef CS_CACHEEX_AIO
	int32_t			cwcacheexgotlg;					// count got localgenerated-flagged CWs
	int32_t			cwcacheexpushlg;				// count pushed localgenerated-flagged CWs
#endif
	uint8_t			cacheex_needfilter;				// flag for cachex mode 3 used with camd35
#ifdef CS_CACHEEX_AIO
	uint8_t			cacheex_aio_checked;			// flag for cacheex aio detection done
#endif
#endif
#ifdef CS_ANTICASC
	struct s_zap_list client_zap_list[15];			// 15 last zappings from client used for ACoSC
#endif
#ifdef WEBIF
	struct s_cwresponse cwlastresptimes[CS_ECM_RINGBUFFER_MAX]; // ringbuffer for last 20 times
	int32_t			cwlastresptimes_last;			// ringbuffer pointer
	int8_t			wihidden;						// hidden in webinterface status
	char			lastreader[64];					// last cw got from this reader
#endif

	uint8_t			ucrc[4];						// needed by monitor and used by camd35
	uint32_t		pcrc;							// password crc
	struct aes_keys	*aes_keys;						// used by camd33 and camd35
	uint16_t		ncd_msgid;
	uint16_t		ncd_client_id;
	uint8_t			ncd_skey[16];					// Also used for camd35 Cacheex to store remote node id

#ifdef MODULE_CCCAM
	void			*cc;
#endif

#ifdef CS_CACHEEX_AIO
#if defined(MODULE_CAMD35) || defined(MODULE_CAMD35_TCP)
	uint8_t 		c35_extmode;
#endif
#endif

#ifdef MODULE_GBOX
	void			*gbox;
	uint16_t		gbox_peer_id;
#endif

#ifdef MODULE_GHTTP
	void			*ghttp;
#endif

	int32_t			port_idx;						// index in server ptab
	int32_t			ncd_server;						// newcamd server

#ifdef CS_ANTICASC
	int32_t			ac_fakedelay;					// When this is -1, the global ac_fakedelay is used
	uint16_t		ac_limit;
	int8_t			ac_penalty;
	struct s_acasc_shm acasc;
#endif

	FTAB			fchid;
	FTAB			ftab;							// user [caid] and ident filter
	CLASSTAB		cltab;

	int32_t			pfd;							// Primary FD, must be closed on exit
	struct s_reader	*reader;						// points to s_reader when cl->typ='r'

	ECM_REQUEST *ecmtask;

	pthread_t		thread;

#ifdef MODULE_SERIAL
	struct s_serial_client *serialdata;
#endif
	// reader common
	int32_t			last_idx;
	uint16_t		idx;

	int8_t			ncd_proto;
	uint8_t			ncd_header[12];

	// camd35
	uint8_t			upwd[64];
	int8_t			is_udp;
	int8_t			stopped;
	uint16_t		lastcaid;
	uint16_t		lastsrvid;
	int32_t			lastpid;
	int8_t			disable_counter;
	uint8_t			lastserial[8];

	// Failban value set bitwise - compared with BAN_
	int32_t			failban;

	LLIST			*cascadeusers;					// s_cascadeuser

	int32_t			n_request[2];					// count for number of request per minute by client

	void			*work_mbuf;						// Points to local data allocated in work_thread when the thread is running
	void			*work_job_data;					// Points to current job_data when work_thread is running

#ifdef MODULE_PANDORA
	int32_t			pand_autodelay;
	uint8_t			pand_send_ecm;
	uint8_t			pand_ignore_ecm;
	uint8_t			pand_md5_key[16];
#endif

#ifdef MODULE_SCAM
	void			*scam;
#endif
	void			*module_data;					// private module data

	struct s_client	*next;							// make client a linked list
	struct s_client	*nexthashed;

	int8_t			start_hidecards;
};

typedef struct s_ecm_whitelist_data
{
	uint16_t		len;
	uint16_t		caid;
	uint32_t		ident;
} ECM_WHITELIST_DATA;

typedef struct s_ecm_whitelist
{
	int32_t			ewnum;
	ECM_WHITELIST_DATA *ewdata;
} ECM_WHITELIST;

typedef struct s_ecm_hdr_whitelist_data
{
	uint16_t		len;
	uint16_t		caid;
	uint32_t		provid;
	uint8_t			header[20];
} ECM_HDR_WHITELIST_DATA;

typedef struct s_ecm_hdr_whitelist
{
	int32_t			ehnum;
	ECM_HDR_WHITELIST_DATA *ehdata;
} ECM_HDR_WHITELIST;

// ratelimit
struct ecmrl
{
	struct timeb	last;
	uint8_t			kindecm;
	bool			once;
	uint8_t			ecmd5[CS_ECMSTORESIZE];
	uint16_t		caid;
	uint32_t		provid;
	uint16_t		srvid;
	uint16_t		chid;
	int32_t			ratelimitecm;
	int32_t			ratelimittime;
	int32_t			srvidholdtime;
};
#define MAXECMRATELIMIT 20

#ifdef MODULE_SERIAL
struct ecmtw
{
	uint16_t		caid;
	uint32_t		provid;
	uint16_t		srvid;
	uint16_t		deg;
	uint16_t		freq;
};
#endif

typedef struct ce_csp_tab_data
{
	int32_t			caid;
	int32_t			cmask;
	int32_t			prid;
	int32_t			srvid;
	int16_t			awtime;
	int16_t			dwtime;
} CECSPVALUETAB_DATA;

typedef struct ce_csp_tab
{
	int32_t			cevnum;
	CECSPVALUETAB_DATA *cevdata;
} CECSPVALUETAB;

typedef struct cacheex_check_cw_tab_data
{
	int32_t			caid;
	int32_t			cmask;
	int32_t			prid;
	int32_t			srvid;
	int8_t			mode;
	uint32_t		counter;
} CWCHECKTAB_DATA;

typedef struct cacheex_check_cw_tab
{
	int32_t			cwchecknum;
	CWCHECKTAB_DATA *cwcheckdata;

} CWCHECKTAB;

typedef struct cacheex_check_cw
{
	int8_t			mode;
	uint32_t		counter;
} CWCHECK;

typedef struct ce_csp_t
{
	int8_t			mode;
	int8_t			maxhop;
#ifdef CS_CACHEEX_AIO
	int8_t			maxhop_lg;
#endif
	CECSPVALUETAB	filter_caidtab;
	uint8_t			allow_request;
	uint8_t			allow_reforward;
	uint8_t			drop_csp;
	uint8_t			allow_filter;
#ifdef CS_CACHEEX_AIO
	uint8_t			allow_maxhop;
#endif
	uint8_t			block_fakecws;
#ifdef CS_CACHEEX_AIO
	uint8_t			cw_check_for_push;
	uint8_t			localgenerated_only;
	CAIDTAB			localgenerated_only_caidtab;
	FTAB			lg_only_tab;
	uint8_t			localgenerated_only_in;
	CAIDTAB			localgenerated_only_in_caidtab;
	FTAB			lg_only_in_tab;
	uint8_t			lg_only_in_aio_only;
	uint8_t			lg_only_remote_settings;
	int32_t			feature_bitfield;
	CAIDVALUETAB	cacheex_nopushafter_tab;
	char			aio_version[12];
#endif
} CECSP;

struct s_emmlen_range
{
	int16_t			min;
	int16_t			max;
};

typedef struct emm_packet_t
{
	uint8_t			emm[MAX_EMM_SIZE];
	int16_t			emmlen;
	uint8_t			caid[2];
	uint8_t			provid[4];
	uint8_t			hexserial[8];					// contains hexserial or SA of EMM
	uint8_t			type;
	uint8_t			skip_filter_check;
	struct s_client *client;
} EMM_PACKET;

struct s_reader										// contains device info, reader info and card info
{
	uint8_t			keepalive;
	uint8_t			changes_since_shareupdate;
	int32_t			resetcycle;						// ECM until reset
	int32_t			resetcounter;					// actual count
	uint32_t		auprovid;						// AU only for this provid
	int8_t			audisabled;						// exclude reader from auto AU
	int8_t			needsemmfirst;					// 0: reader descrambles without emm first, 1: reader needs emms before it can descramble
	struct timeb	emm_last;							// time of last successfully written emm
	int8_t			smargopatch;
	int8_t			autospeed;						// 1 clockspeed set according to atr f max
	struct s_client	*client;						// pointer to 'r'client this reader is running in
	LLIST			*ll_entitlements;				// entitlements
	int8_t			enable;
	int8_t			active;
	int8_t			dropbadcws;						// Schlocke: 1=drops cw if checksum is wrong. 0=fix checksum (default)
	int8_t			disablecrccws;					// 1=disable cw checksum test. 0=enable checksum check
	uint64_t		grp;
	int8_t			fallback;
	FTAB			fallback_percaid;
	FTAB			localcards;
	FTAB			disablecrccws_only_for;			// ignore checksum for selected caid provid
#ifdef READER_CRYPTOWORKS
	int8_t			needsglobalfirst;				// 0:Write one Global EMM for SHARED EMM disabled 1:Write one Global EMM for SHARED EMM enabled
#endif
#if defined(READER_NAGRA_MERLIN) || defined(READER_NAGRA)
	uint8_t			nuid[4];
	uint8_t			nuid_length;
	uint8_t			cwekey[16];
	uint8_t			cwekey_length;
#endif
#ifdef READER_NAGRA_MERLIN
	uint8_t			irdid[4];
	uint8_t			irdid_length;
	uint8_t			public_exponent[3];
	uint8_t			public_exponent_length;
	uint8_t			mod1[112];
	uint8_t			mod1_length;
	uint8_t			data50[80];
	uint8_t			data50_length;
	uint8_t			mod50[80];
	uint8_t			mod50_length;
	uint8_t			key60[96];
	uint8_t			key60_length;
	uint8_t			exp60[96];
	uint8_t			exp60_length;
	uint8_t			kdt05_00[216];
	uint8_t			kdt05_10[208];
	uint8_t			cardid[8];
	uint8_t			edata[255];
	uint8_t			dt5num;
	uint8_t			out[255];
	uint8_t			ideakey1[16];
	uint8_t			block3[8];
	uint8_t			v[8];
	uint8_t			iout[8];
	uint8_t			data2[4];
	uint8_t			data[0x80];
	uint8_t			step1[0x60];
	uint8_t			step2[0x68];
	uint8_t			step3[0x6c];
	uint8_t			encrypted[0x68];
	uint8_t			result[104];
	uint8_t			stillencrypted[0x50];
	uint8_t			resultrsa[0x50];
	uint32_t		cak7_restart;
	uint32_t		cak7_seq;
	uint8_t			cak7_camstate;
	uint8_t			cak7_aes_key[32];
	uint8_t			cak7_aes_iv[16];
	struct timeb	last_refresh;
#endif
#ifdef CS_CACHEEX
	CECSP			cacheex;						// CacheEx Settings
#endif
	int32_t			typ;
	char			label[64];
#ifdef WEBIF
	char			*description;
#endif
	char			device[128];
	uint16_t		slot;							// in case of multiple slots like sc8in1; first slot = 1
	int32_t			handle;							// device handle
	int64_t			handle_nr;						// device handle_nr for mutiple readers same driver
	int32_t			fdmc;							// device handle for multicam
	int32_t			detect;
	int32_t			mhz;							// actual clock rate of reader in 10khz steps
	int32_t			cardmhz;						// standard clock speed your card should have in 10khz steps; normally 357 but for Irdeto cards 600
	int32_t			divider;						// PLL divider for internal readers
	int32_t			r_port;
	char			r_usr[64];
	char			r_pwd[64];
	int32_t			l_port;
	CAIDTAB			ctab;
	uint32_t		boxid;
	int8_t			nagra_read;						// read nagra ncmed records: 0 Disabled (default), 1 read all records, 2 read valid records only
	int8_t			detect_seca_nagra_tunneled_card;
	int8_t			force_irdeto;
	uint8_t			boxkey[16];						// n3 boxkey 8 bytes, seca sessionkey 16 bytes, viaccess camid 4 bytes
	uint8_t			boxkey_length;
	uint8_t			rsa_mod[120];					// rsa modulus for nagra cards.
	uint8_t			rsa_mod_length;
	uint8_t			des_key[128];					// 3des key for Viaccess 16 bytes, des key for Dre 128 bytes
	uint8_t			des_key_length;
	uint8_t			atr[64];
	uint8_t			card_atr[64];					// ATR readed from card
	int8_t			card_atr_length;				// length of ATR
	int8_t			seca_nagra_card;				// seca nagra card
	int32_t			atrlen;
	SIDTABS			sidtabs;
	SIDTABS			lb_sidtabs;
	uint8_t			hexserial[8];
	int32_t			nprov;
	uint8_t			prid[CS_MAXPROV][8];
	uint8_t			sa[CS_MAXPROV][4];				// viaccess & seca
	uint8_t			read_old_classes;				// viaccess
	uint8_t			maturity;						// viaccess & seca maturity level
	uint16_t		caid;
	uint16_t		b_nano;
	uint16_t		s_nano;
	int8_t			ecmcommand;						// used for filtering nagra bad ecm commands
	uint8_t			ecmcommandcache[5];				// cachebuff for ecm commands
	int32_t			blockemm;
	int32_t			saveemm;
	LLIST			*blockemmbylen;
	char			*emmfile;
	char			pincode[5];
	int8_t			logemm;
	int8_t			cachemm;
	int16_t			rewritemm;
	int16_t			deviceemm;						// catch device specific emms (so far only used for viaccess)
	int8_t			card_status;
	int8_t			deprecated;						// if 0 ATR obeyed, if 1 default speed (9600) is chosen; for devices that cannot switch baudrate
	struct			s_module ph;
	const struct s_cardreader *crdr;
	void			*crdr_data;						// Private card reader data
	bool			crdr_flush;						// sci readers may disable flush per reader
	const struct s_cardsystem *csystem;
	void			*csystem_data;					// Private card system data
	bool			csystem_active;
	uint8_t			ncd_key[14];
	uint8_t			ncd_skey[16];
	int8_t			ncd_connect_on_init;
	int8_t			ncd_disable_server_filt;
	int8_t			ncd_proto;
	int8_t			currenthops;					// number of hops (cccam & gbox)
	int8_t			sh4_stb;						// to set sh4 type box used to identify sci type.
#ifdef MODULE_CCCAM
	char			cc_version[7];					// cccam version
	char			cc_build[7];					// cccam build number
	int8_t			cc_maxhops;						// cccam max distance
	int8_t			cc_mindown;						// cccam min downhops
	int8_t			cc_want_emu;					// Schlocke: Client want to have EMUs, 0 - NO; 1 - YES
	uint32_t		cc_id;
	int8_t			cc_keepalive;
	int8_t			cc_hop;							// For non-cccam reader: hop for virtual cards
	int8_t			cc_reshare;
	int32_t			cc_reconnect;					// reconnect on ecm-request timeout
#endif
	int8_t			tcp_connected;
	int32_t			tcp_ito;						// inactivity timeout
	int32_t			tcp_rto;						// reconnect timeout
	int32_t			tcp_reconnect_delay;			// max tcp connection block delay

	struct timeb	tcp_block_connect_till;			// time tcp connect ist blocked
	int32_t			tcp_block_delay;				// incrementing block time
	time_t			last_g;							// get (if last_s-last_g>tcp_rto - reconnect )
	time_t			last_s;							// send
	time_t			last_check;						// last checked
	time_t			last_poll;						// last poll
	FTAB			fchid;
	FTAB			ftab;
	CLASSTAB		cltab;
	ECM_WHITELIST	ecm_whitelist;
	ECM_HDR_WHITELIST ecm_hdr_whitelist;
	int32_t			brk_pos;
	int32_t			msg_idx;
	int32_t			secatype;						// 0=not determined, 2=seca2, 3=nagra(~seca3) this is only valid for localreaders!
	uint32_t		maxreadtimeout;					// in us
	uint32_t		minreadtimeout;					// in us
	uint32_t		maxwritetimeout;				// in us
	uint32_t		minwritetimeout;				// in us
#if defined(WEBIF) || defined(LCDSUPPORT)
	int32_t			emmwritten[4];					// count written EMM
	int32_t			emmskipped[4];					// count skipped EMM
	int32_t			emmerror[4];					// count error EMM
	int32_t			emmblocked[4];					// count blocked EMM
	int32_t			webif_emmwritten[4];			// count written EMM for webif reader info
	int32_t			webif_emmskipped[4];			// count skipped EMM for webif reader info
	int32_t			webif_emmerror[4];				// count error EMM for reader webif info
	int32_t			webif_emmblocked[4];			// count blocked EMM for reader webif info
	int32_t			lbvalue;						// loadbalance Value
#endif
#ifdef WITH_AZBOX
	int32_t			azbox_mode;
#endif
	int32_t			use_gpio;						// Should this reader use GPIO functions
	int				gpio_outen;						// fd of opened /dev/gpio/outen
	int				gpio_out;						// fd of opened /dev/gpio/out
	int				gpio_in;						// fd of opened /dev/gpio/in
	uint32_t		gpio;							// gpio addr
#ifdef WITH_CARDREADER
	// variables from icc_async.h start
	int32_t			convention;						// Convention of this ICC
	uint8_t			protocol_type;					// Type of protocol
	uint32_t		current_baudrate;				// (for overclocking uncorrected) baudrate to prevent unnecessary conversions from/to termios structure
	double			worketu;						// in us for internal and external readers calculated (1/D)*(F/cardclock)*1000000
	uint32_t		read_timeout;					// Max timeout (ETU) to receive characters
	uint32_t		char_delay;						// Delay (ETU) after transmiting each successive char
	uint32_t		block_delay;					// Delay (ms) after starting to transmit
	uint32_t		BWT, CWT;						// (for overclocking uncorrected) block waiting time, character waiting time, in ETU
	// variables from io_serial.h
	int32_t			written;						// keep score of how much bytes are written to serial port, since they are echoed back they have to be read
	// variables from protocol_t1.h
	uint16_t		ifsc;							// Information field size for the ICC
	uint8_t			ns;								// Send sequence number
	int16_t			smartdev_found;
	int16_t			smart_type;
	uint16_t		statuscnt;
	uint16_t		modemstat;
#endif
#ifdef READER_CRYPTOWORKS
	EMM_PACKET		*last_g_emm;					// last global EMM
	bool			last_g_emm_valid;				// status of last global EMM
#endif
	uint8_t			rom[15];
	uint8_t			irdId[4];
	uint8_t			payload4C[15];
	uint16_t		VgCredit;
	uint16_t		VgPin;
	uint8_t			VgFuse;
	uint8_t			VgCountryC[3];
	uint8_t			VgRegionC[8];
	uint8_t			VgLastPayload[6];
#ifdef WITH_LB
	int32_t			lb_weight;						// loadbalance weight factor, if unset, weight=100. The higher the value, the higher the usage-possibility
	int8_t			lb_force_fallback;				// force this reader as fallback if fallback or fallback_percaid paramters set
	int32_t			lb_usagelevel;					// usagelevel for loadbalancer
	int32_t			lb_usagelevel_ecmcount;
	struct timeb	lb_usagelevel_time;				// time for counting ecms, this creates usagelevel
	struct timeb	lb_last;						// time for oldest reader
	LLIST			*lb_stat;						// loadbalancer reader statistics
	CS_MUTEX_LOCK	lb_stat_lock;
	int32_t			lb_stat_busy;					// do not add while saving
#endif

	AES_ENTRY		*aes_list;						// multi AES linked list
	int8_t			ndsversion;						// 0 auto (default), 1 NDS1, 12 NDS1+, 2 NDS2
	time_t			card_valid_to;
	// ratelimit
	int32_t			ratelimitecm;
	int32_t			ratelimittime;					// ratelimit time in ms (everything below 60 ms is converted to ms by applying *1000)
	int8_t			ecmunique;						// check for matching ecm hash in ratelimitslot
	int32_t			srvidholdtime;					// time in ms to keep srvid in ratelimitslot (during this time not checked for ecmunique!)
													// (everything below 60 ms is converted to ms by applying *1000)
	struct timeb	lastdvbapirateoverride;
	uint32_t		ecmsok;
#ifdef CS_CACHEEX_AIO
	uint32_t		ecmsoklg;
#endif
	uint32_t		webif_ecmsok;
	uint32_t		ecmsnok;
	uint32_t		webif_ecmsnok;
	uint32_t		ecmstout;
	uint32_t		webif_ecmstout;
	uint32_t		ecmnotfoundlimit;				// config setting. restart reader if ecmsnok >= ecmnotfoundlimit
	int32_t			ecmsfilteredhead;				// count filtered ECM's by ECM Headerwhitelist
	int32_t			ecmsfilteredlen;				// count filtered ECM's by ECM Whitelist
	int32_t			webif_ecmsfilteredhead;			// count filtered ECM's by ECM Headerwhitelist to readers ecminfo
	int32_t			webif_ecmsfilteredlen;			// count filtered ECM's by ECM Whitelist to readers ecm info
	float			ecmshealthok;
#ifdef CS_CACHEEX_AIO
	float			ecmshealthoklg;
#endif
	float			ecmshealthnok;
	float			ecmshealthtout;
	int32_t			cooldown[2];
	int8_t			cooldownstate;
	struct timeb	cooldowntime;
	struct ecmrl	rlecmh[MAXECMRATELIMIT];
	int8_t			fix_07;
	int8_t			fix_9993;
	int8_t			readtiers;						// method to get videoguard tiers
	uint8_t			ins7E[0x1A + 1];
	uint8_t			ins7E11[0x01 + 1];
	uint8_t			ins42[0x25 + 1];
	uint8_t			ins2e06[0x04 + 1];
	int8_t			ins7e11_fast_reset;
	uint8_t			k1_generic[0x10 + 1];			// k1 for generic pairing mode
	uint8_t			k1_unique[0x10 + 1];			// k1 for unique pairing mode
	uint8_t			sc8in1_dtrrts_patch;			// fix for kernel commit 6a1a82df91fa0eb1cc76069a9efe5714d087eccd

#ifdef READER_VIACCESS
	uint8_t			initCA28;						// To set when CA28 succeed
	uint32_t		key_schedule1[32];
	uint32_t		key_schedule2[32];
#endif

#if defined(READER_DRE) || defined(READER_DRECAS)
	char			*userscript;
	uint32_t		force_ua;
#endif

#ifdef READER_DRECAS
	char			*stmkeys;
#endif

#ifdef MODULE_GBOX
	uint8_t			gbox_maxdist;
	uint8_t			gbox_maxecmsend;
	uint8_t			gbox_reshare;
	int8_t			gbox_cccam_reshare;
	char			last_gsms[128];
	uint16_t		gbox_remm_peer;
	uint16_t		gbox_gsms_peer;
	uint8_t			gbox_force_remm;
	uint16_t		gbox_cw_src_peer;
	uint8_t			gbox_crd_slot_lev;
	FTAB			ccc_gbx_reshare_ident;
	uint8_t			send_offline_cmd;
	uint16_t		nb_send_crds;
#endif

#ifdef MODULE_PANDORA
	uint8_t			pand_send_ecm;
#endif
#ifdef MODULE_GHTTP
	uint8_t			ghttp_use_ssl;
#endif
#ifdef WITH_EMU
	FTAB			emu_auproviders;				// AU providers for Emu reader
	int8_t			emu_datecodedenabled;			// date-coded keys for BISS
	LLIST			*ll_biss2_rsa_keys;				// BISS2 RSA keys - Read from external PEM files
#endif
	uint8_t			cnxlastecm;						// == 0 - last ecm has not been paired ecm, > 0 last ecm has been paired ecm
	LLIST			*emmstat;						// emm stats
	CS_MUTEX_LOCK	emmstat_lock;
	struct s_reader	*next;
};

struct s_cpmap
{
	uint16_t		caid;
	uint32_t		provid;
	uint16_t		sid;
	uint16_t		chid;
	uint16_t		dwtime;
	struct s_cpmap	*next;
};

struct s_auth
{
	char			usr[64];
	char			*pwd;
#ifdef WEBIF
	char			*description;
#endif
	int8_t			uniq;
#ifdef CS_CACHEEX
	CECSP			cacheex;						// CacheEx Settings
	uint8_t			no_wait_time;
	uint8_t			disablecrccacheex;
	FTAB			disablecrccacheex_only_for;
#endif
	int16_t			allowedprotocols;
	LLIST			*aureader_list;
	int8_t			autoau;
	uint8_t			emm_reassembly;					// 0 = OFF; 1 = OFF / DVBAPI = ON; 2 = ON (default)
	int8_t			monlvl;
	uint64_t		grp;
	int32_t			tosleep;
	int32_t			umaxidle;
	CAIDTAB			ctab;
	SIDTABS			sidtabs;
	FTAB			fchid;
	FTAB			ftab;							// user [caid] and ident filter
	CLASSTAB		cltab;
	TUNTAB			ttab;
	int8_t			preferlocalcards;
	uint32_t		max_connections;
#ifdef CS_ANTICASC
	int32_t			ac_fakedelay;					// When this is -1, the global ac_fakedelay is used
	int32_t			ac_users;						// 0 - unlimited
	int8_t			ac_penalty;						// 0 - log, >0 - fake dw
	struct s_acasc	ac_stat;
	int8_t			acosc_max_ecms_per_minute;		// user value 0 - unlimited
	int8_t			acosc_max_active_sids;			// user value 0 - unlimited
	int8_t			acosc_zap_limit;				// user value 0 - unlimited
	int8_t			acosc_penalty;					// user value penalty
	int32_t			acosc_penalty_duration;			// user value how long is penalty activ in sek.
	time_t			acosc_penalty_until;
	int8_t			acosc_penalty_active;			// 0-deaktiv 1-max_active_sids 2-zap_limit 3-max_ecms_per_minute 4-penaly_duration
	int32_t			acosc_delay;					// user value
	int8_t			acosc_user_zap_count;
	time_t			acosc_user_zap_count_start_time;
#endif
#ifdef WITH_LB
	int32_t			lb_nbest_readers;				// When this is -1, the global lb_nbest_readers is used
	int32_t			lb_nfb_readers;					// When this is -1, the global lb_nfb_readers is used
	CAIDVALUETAB	lb_nbest_readers_tab;			// like nbest_readers, but for special caids
#endif
	IN_ADDR_T		dynip;
	char			*dyndns;
	time_t			expirationdate;
	time_t			firstlogin;
	uint32_t		allowedtimeframe[SIZE_SHORTDAY][24][2]; // day[0-sun to 6-sat, 7-ALL],hours,minutes use as binary flags to reduce mem usage
	uint8_t			allowedtimeframe_set;			// flag for internal use to mention if allowed time frame is used
	int8_t			c35_suppresscmd08;
	uint8_t			c35_sleepsend;
	int8_t			ncd_keepalive;
#ifdef MODULE_CCCAM
	int32_t			cccmaxhops;
	int8_t			cccreshare;
	int8_t			cccignorereshare;
	int8_t			cccstealth;
#endif
	int8_t			disabled;
	int32_t			failban;

	int32_t			cwfound;
	int32_t			cwcache;
	int32_t			cwnot;
	int32_t			cwtun;
	int32_t			cwignored;
	int32_t			cwtout;
#ifdef CW_CYCLE_CHECK
	int32_t			cwcycledchecked;				// count checked cwcycles per client
	int32_t			cwcycledok;						// count pos checked cwcycles per client
	int32_t			cwcyclednok;					// count neg checked cwcycles per client
	int32_t			cwcycledign;					// count ign cwcycles per client
	int8_t			cwc_disable;					// disable cwc checking for this Client
#endif
	int32_t			emmok;
	int32_t			emmnok;
#ifdef CS_CACHEEX
	int32_t			cwcacheexpush;					// count pushed ecms/cws
	int32_t			cwcacheexgot;					// count got ecms/cws
	int32_t			cwcacheexhit;					// count hit ecms/cws
	int32_t			cwcacheexerr;					// cw=00 or chksum wrong
	int32_t			cwcacheexerrcw;					// Same Hex, different CW
	int32_t			cwc_info;						// count of in/out comming cacheex ecms with CWCinfo
#ifdef CS_CACHEEX_AIO
	int32_t			cwcacheexgotlg;					// count got localgenerated-flagged CWs
	int32_t			cwcacheexpushlg;				// count pushed localgenerated-flagged CWs
#endif
#endif
	struct s_auth	*next;
};


struct s_srvid_caid
{
	uint16_t		caid;
	uint16_t		nprovid;
	uint32_t		*provid;
};

struct s_srvid
{
	uint16_t		srvid;
	int8_t			ncaid;
	struct s_srvid_caid *caid;
	char			*data;
	const char		*prov;
	const char		*name;
	const char		*type;
	const char		*desc;
	struct s_srvid	*next;
};

struct s_rlimit
{
	struct ecmrl	rl;
	struct s_rlimit	*next;
};

struct s_cw
{
	uint8_t			cw[16];
};

struct s_fakecws
{
	uint32_t		count;
	struct s_cw		*data;
};

#ifdef MODULE_SERIAL
struct s_twin
{
	struct ecmtw	tw;
	struct s_twin	*next;
};
#endif

struct s_tierid
{
	uint16_t		tierid;
	int8_t			ncaid;
	uint16_t		caid[10];
	char			name[33];
	struct s_tierid	*next;
};

struct s_provid
{
	uint16_t		caid;
	uint16_t		nprovid;
	uint32_t		*provid;
	char			prov[33];
	char			sat[33];
	char			lang[33];
	struct s_provid	*next;
};

struct s_ip
{
	IN_ADDR_T		ip[2];
	struct s_ip		*next;
};

struct s_global_whitelist
{
	uint32_t		line;							// linenr of oscam.whitelist file, starting with 1
	char			type;							// w or i or l
	uint16_t		caid;
	uint32_t		provid;
	uint16_t		srvid;
	uint16_t		chid;
	uint16_t		pid;
	uint16_t		ecmlen;
	uint16_t		mapcaid;
	uint32_t		mapprovid;
	struct			s_global_whitelist *next;
};

struct s_cacheex_matcher
{
	uint32_t		line;							// linenr of oscam.Cacheex file, starting with 1
	char			type;							// m
	uint16_t		caid;
	uint32_t		provid;
	uint16_t		srvid;
	uint16_t		chid;
	uint16_t		pid;
	uint16_t		ecmlen;

	uint16_t		to_caid;
	uint32_t		to_provid;
	uint16_t		to_srvid;
	uint16_t		to_chid;
	uint16_t		to_pid;
	uint16_t		to_ecmlen;

	int32_t			valid_from;
	int32_t			valid_to;

	struct s_cacheex_matcher *next;
};

struct s_config
{
	int32_t			nice;
	uint32_t		netprio;
	uint32_t		ctimeout;
	uint32_t		ftimeout;
	CAIDVALUETAB	ftimeouttab;
	uint32_t		cmaxidle;
	int32_t			ulparent;
	uint32_t		delay;
	int32_t			bindwait;
	int32_t			tosleep;
	IN_ADDR_T		srvip;
	char			*usrfile;
	char			*cwlogdir;
	char			*emmlogdir;
	char			*logfile;
	char			*mailfile;
	int8_t			disablecrccws;					// 1=disable cw checksum test. 0=enable checksum check
	FTAB			disablecrccws_only_for;			// ignore checksum for selected caid provid
	uint8_t			logtostdout;
	uint8_t			logtosyslog;
	int8_t			logduplicatelines;
	int32_t			initial_debuglevel;
	char			*sysloghost;
	int32_t			syslogport;
#if defined(WEBIF) || defined(MODULE_MONITOR)
	uint32_t		loghistorylines;
#endif
	int8_t			disablelog;
	int8_t			disablemail;
	int8_t			disableuserfile;
	int8_t			usrfileflag;
	struct s_auth	*account;
	struct s_srvid	*srvid[16];
	struct s_tierid	*tierid;
	struct s_provid	*provid;
	struct s_sidtab	*sidtab;
#ifdef MODULE_MONITOR
	int32_t			mon_port;
	IN_ADDR_T		mon_srvip;
	struct s_ip		*mon_allowed;
	uint8_t			mon_level;
#endif
	int32_t			aulow;
	int32_t			hideclient_to;
#ifdef WEBIF
	int32_t			http_port;
	IN_ADDR_T		http_srvip;
	char			*http_user;
	char			*http_pwd;
	char			*http_css;
	int8_t			http_prepend_embedded_css;
	char			*http_jscript;
	char			*http_tpl;
	char			*http_piconpath;
	char			*http_script;
#ifndef WEBIF_JQUERY
	char			*http_extern_jquery;
#endif
	int32_t			http_refresh;
	int32_t			poll_refresh;
	int8_t			http_hide_idle_clients;
	char			*http_hide_type;
	int8_t			http_showpicons;
	int8_t			http_picon_size;
	int8_t			http_status_log;
	int8_t			http_showmeminfo;
	int8_t			http_showecminfo;
	int8_t			http_showloadinfo;
	int8_t			http_showuserinfo;
	int8_t			http_showreaderinfo;
	int8_t			http_showcacheexinfo;
	struct s_ip		*http_allowed;
	int8_t			http_readonly;
	IN_ADDR_T		http_dynip[MAX_HTTP_DYNDNS];
	uint8_t			http_dyndns[MAX_HTTP_DYNDNS][64];
	int8_t			http_use_ssl;
	int8_t			https_force_secure_mode;
	char			*http_cert;
	char			*http_help_lang;
	char			*http_locale;
	char			*http_oscam_label;
	int32_t			http_emmu_clean;
	int32_t			http_emms_clean;
	int32_t			http_emmg_clean;
#endif
	int8_t			http_full_cfg;
	int8_t			http_overwrite_bak_file;
	int32_t			failbantime;
	int32_t			failbancount;
	LLIST			*v_list;						// Failban list
#ifdef MODULE_CAMD33
	int32_t			c33_port;
	IN_ADDR_T		c33_srvip;
	uint8_t			c33_key[16];
	int32_t			c33_crypted;
	int32_t			c33_passive;
	struct s_ip		*c33_plain;
#endif
#if defined(MODULE_CAMD35) || defined(MODULE_CAMD35_TCP)
	int32_t			c35_port;
	IN_ADDR_T		c35_srvip;
	int8_t			c35_tcp_suppresscmd08;
	int8_t			c35_udp_suppresscmd08;
	PTAB			c35_tcp_ptab;
	IN_ADDR_T		c35_tcp_srvip;
#endif
	int8_t			c35_suppresscmd08;				// used in cccam module
	int8_t			getblockemmauprovid;
	int32_t			umaxidle;						//User max Idle
#ifdef MODULE_NEWCAMD
	PTAB			ncd_ptab;
	IN_ADDR_T		ncd_srvip;
	uint8_t			ncd_key[14];
	int8_t			ncd_keepalive;
	int8_t			ncd_mgclient;
	struct s_ip		*ncd_allowed;
#endif
#ifdef MODULE_RADEGAST
	int32_t			rad_port;
	IN_ADDR_T		rad_srvip;
	struct s_ip		*rad_allowed;
	char			*rad_usr;
#endif
#ifdef MODULE_CCCAM
	uint16_t		cc_port[CS_MAXPORTS];
	int8_t			cc_reshare;
	int8_t			cc_ignore_reshare;
	int32_t			cc_update_interval;
	IN_ADDR_T		cc_srvip;
	char			cc_version[7];
	int8_t			cc_minimize_cards;
	int8_t			cc_keep_connected;
	int8_t			cc_stealth;
	int8_t			cc_reshare_services;
	int8_t			cc_forward_origin_card;
	uint8_t			cc_fixed_nodeid[8];
	uint32_t		cc_recv_timeout;				// The poll() timeout parameter in ms. Default: DEFAULT_CC_RECV_TIMEOUT (2000 ms).
#endif
#ifdef MODULE_GBOX
	#define			GBOX_MY_VERS_DEF		0x2A
	#define			GBOX_MY_CPU_API_DEF	0x61
	#define			GBOX_MAX_PROXY_CARDS	32
	#define			GBOX_MAX_IGNORED_PEERS 16
	#define			GBOX_MAX_BLOCKED_ECM	16
	#define			GBOX_MAX_REMM_PEERS	8
	#define			GBOX_MAX_DEST_PEERS	16
	#define			GBOX_MAX_MSG_TXT		127
	uint16_t		gbox_port[CS_MAXPORTS];
	char			*gbox_hostname;
	uint32_t		gbox_reconnect;
	uint32_t		gbox_password;
	unsigned long	gbox_proxy_card[GBOX_MAX_PROXY_CARDS];
	int8_t			gbox_proxy_cards_num;
	uint32_t		gbox_my_vers;
	uint8_t			gbox_my_cpu_api;
	uint8_t			gsms_dis;
	uint8_t			log_hello;
	uint8_t			dis_attack_txt;
	char			*gbox_tmp_dir;
	uint8_t			cc_gbx_reshare_en;
	uint16_t		gbox_ignored_peer[GBOX_MAX_IGNORED_PEERS];
	uint8_t			gbox_ignored_peer_num;
	uint16_t		accept_remm_peer[GBOX_MAX_REMM_PEERS];
	uint8_t			accept_remm_peer_num;
	uint16_t		gbox_block_ecm[GBOX_MAX_BLOCKED_ECM];
	uint8_t			gbox_block_ecm_num;
	uint8_t			gbox_save_gsms;
	uint8_t			gbox_msg_type;
	uint16_t		gbox_dest_peers[GBOX_MAX_DEST_PEERS];
	uint8_t			gbox_dest_peers_num;
	char				gbox_msg_txt[GBOX_MAX_MSG_TXT+1];
#endif
#ifdef MODULE_SERIAL
	char			*ser_device;
#endif
	int32_t			max_log_size;
	int8_t			waitforcards;
	int32_t			waitforcards_extra_delay;
	int8_t			preferlocalcards;
	int32_t			reader_restart_seconds;			// schlocke: reader restart auf x seconds, disable = 0
	int8_t			dropdups;						// drop duplicate logins


	// Loadbalancer-Config:
	int32_t			lb_mode;						// schlocke: reader loadbalancing mode
	int32_t			lb_auto_betatunnel;				// automatic selection of betatunnel convertion based on learned data
	int32_t			lb_auto_betatunnel_mode;		// automatic selection of betatunnel direction
#ifdef WITH_LB
	int32_t			lb_save;						// schlocke: load/save statistics to file, save every x ecms
	int32_t			lb_nbest_readers;				// count of best readers
	int32_t			lb_nfb_readers;					// count of fallback readers
	int32_t			lb_min_ecmcount;				// minimal ecm count to evaluate lbvalues
	int32_t			lb_max_ecmcount;				// maximum ecm count before reseting lbvalues
	int32_t			lb_reopen_seconds;				// time between retrying failed readers/caids/prov/srv
	int8_t			lb_reopen_invalid;				// default=1; if 0, rc=E_INVALID will be blocked until stats cleaned
	int8_t			lb_force_reopen_always;			// force reopening immediately all failing readers if no matching reader found
	int32_t			lb_retrylimit;					// reopen only happens if reader response time > retrylimit
	CAIDVALUETAB	lb_retrylimittab;
	CAIDVALUETAB	lb_nbest_readers_tab;			// like nbest_readers, but for special caids
	CAIDTAB			lb_noproviderforcaid;			// do not store loadbalancer stats with providers for this caid
	char			*lb_savepath;					// path where the stat file is save. Empty=default=/tmp/.oscam/stat
	int32_t			lb_stat_cleanup;				// duration in hours for cleaning old statistics
	int32_t			lb_max_readers;					// limit the amount of readers during learning
	int32_t			lb_auto_betatunnel_prefer_beta; // prefer-beta-over-nagra factor
	int32_t			lb_auto_timeout;				// Automatic timeout by loadbalancer statistics
	int32_t			lb_auto_timeout_p;				// percent added to avg time as timeout time
	int32_t			lb_auto_timeout_t;				// minimal time added to avg time as timeout time
#endif
	int32_t			resolve_gethostbyname;
	int8_t			double_check;					// schlocke: Double checks each ecm+dcw from two (or more) readers
	FTAB			double_check_caid;				// do not store loadbalancer stats with providers for this caid

#ifdef HAVE_DVBAPI
	int8_t			dvbapi_enabled;
	int8_t			dvbapi_au;
	char			*dvbapi_usr;
	int8_t			dvbapi_boxtype;
	int8_t			dvbapi_pmtmode;
	int8_t			dvbapi_requestmode;
	int32_t			dvbapi_listenport;				// TCP port to listen instead of camd.socket (network mode, default=0 -> disabled)
	SIDTABS			dvbapi_sidtabs;
	int32_t			dvbapi_delayer;					// delayer ms, minimum time to write cw
	int8_t			dvbapi_ecminfo_file;			// Enable or disable ecm.info file creation
	int8_t			dvbapi_ecminfo_type;
	int8_t			dvbapi_read_sdt;
	int8_t			dvbapi_write_sdt_prov;
	int8_t			dvbapi_extended_cw_api;
#endif

#ifdef CS_ANTICASC
	int8_t			ac_enabled;
	int32_t			ac_users;						// num of users for account (0 - default)
	int32_t			ac_stime;						// time to collect AC statistics (3 min - default)
	int32_t			ac_samples;						// qty of samples
	int8_t			ac_penalty;						// 0 - write to log
	int32_t			ac_fakedelay;					// 100-1000 ms
	int32_t			ac_denysamples;
	char			*ac_logfile;
	struct s_cpmap	*cpmap;
	int8_t			acosc_enabled;
	int8_t			acosc_max_ecms_per_minute;		// global value 0 - unlimited
	int8_t			acosc_max_active_sids;			// global value 0 - unlimited
	int8_t			acosc_zap_limit;				// global value 0 - unlimited
	int32_t			acosc_penalty_duration;			// global value how long is penalty activ in sek.
	int8_t			acosc_penalty;					// global value
	int32_t			acosc_delay;					// global value
#endif

#ifdef LEDSUPPORT
	int8_t			enableled;						// 0=disabled led, 1=enable led for routers, 2=enable qboxhd led
#endif

#ifdef LCDSUPPORT
	int8_t			enablelcd;
	char			*lcd_output_path;
	int32_t			lcd_hide_idle;
	int32_t			lcd_write_intervall;
#endif

#ifdef MODULE_PANDORA
	int8_t			pand_skip_send_dw;
	struct s_ip		*pand_allowed;
	char			*pand_usr;
	char			*pand_pass;
	int8_t			pand_ecm;
	int32_t			pand_port;
	IN_ADDR_T		pand_srvip;
#endif

#ifdef MODULE_SCAM
	int32_t			scam_port;
	IN_ADDR_T		scam_srvip;
	struct s_ip		*scam_allowed;
#endif

#ifdef WITH_EMU
	char			*emu_stream_source_host;
	int32_t			emu_stream_source_port;
	char			*emu_stream_source_auth_user;
	char			*emu_stream_source_auth_password;
	int32_t			emu_stream_relay_port;
	uint32_t		emu_stream_ecm_delay;
	int8_t			emu_stream_relay_enabled;
	int8_t			emu_stream_emm_enabled;
	CAIDTAB			emu_stream_relay_ctab;			// use the stream server for these caids
#endif

	int32_t			max_cache_time;					// seconds ecms are stored in ecmcwcache
	int32_t			max_hitcache_time;				// seconds hits are stored in cspec_hitcache (to detect dyn wait_time)

	int8_t			reload_useraccounts;
	int8_t			reload_readers;
	int8_t			reload_provid;
	int8_t			reload_services_ids;
	int8_t			reload_tier_ids;
	int8_t			reload_fakecws;
	int8_t			reload_ac_stat;
	int8_t			reload_log;

	int8_t			block_same_ip;					// 0=allow all, 1=block client requests to reader with same ip   (default=1)
	int8_t			block_same_name;				// 0=allow all, 1=block client requests to reader with same name (default=1)

#ifdef CS_CACHEEX
#ifdef CS_CACHEEX_AIO
	uint32_t		cw_cache_size;
	uint32_t		cw_cache_memory;
	CWCHECKTAB		cw_cache_settings;

	uint32_t		ecm_cache_size;
	uint32_t		ecm_cache_memory;
	int32_t			ecm_cache_droptime;
#endif
	uint8_t			wait_until_ctimeout;
	CWCHECKTAB		cacheex_cwcheck_tab;
	IN_ADDR_T		csp_srvip;
	int32_t			csp_port;
	CECSPVALUETAB	cacheex_wait_timetab;
	CAIDVALUETAB	cacheex_mode1_delay_tab;
#ifdef CS_CACHEEX_AIO
	CAIDVALUETAB	cacheex_nopushafter_tab;
	uint8_t			waittime_block_start;
	uint16_t		waittime_block_time;
#endif
	CECSP			csp;							// CSP Settings
	uint8_t			cacheex_enable_stats;			// enable stats
	struct s_cacheex_matcher *cacheex_matcher;
#ifdef CS_CACHEEX_AIO
	uint8_t			cacheex_dropdiffs;
	uint8_t			cacheex_lg_only_remote_settings;
	uint8_t			cacheex_localgenerated_only;
	CAIDTAB			cacheex_localgenerated_only_caidtab;
	FTAB			cacheex_lg_only_tab;
	uint8_t			cacheex_localgenerated_only_in;
	CAIDTAB			cacheex_localgenerated_only_in_caidtab;
	FTAB			cacheex_lg_only_in_tab;
	uint8_t			cacheex_lg_only_in_aio_only;
	CECSPVALUETAB	cacheex_filter_caidtab;
	CECSPVALUETAB	cacheex_filter_caidtab_aio;
	uint64_t		cacheex_push_lg_groups;
#endif
#endif

#ifdef CW_CYCLE_CHECK
	int8_t			cwcycle_check_enable;			// on or off
	CAIDTAB			cwcycle_check_caidtab;			// Caid for CW Cycle Check
	int32_t			keepcycletime;					// how long stay the learned Cycletime in Memory
	int32_t			maxcyclelist;					// max size of cwcyclelist
	int8_t			onbadcycle;						// what to do on bad cwcycle
	int8_t			cwcycle_dropold;				// what to do on old ecmd5/cw
	int8_t			cwcycle_sensitive;
	int8_t			cwcycle_allowbadfromffb;		// allow Bad cycles from Fixed Fallbackreader
	int8_t			cwcycle_usecwcfromce;			// Use CWC Info from Cacheex Sources for CWC Checking
#endif

	// Global whitelist:
	struct s_global_whitelist *global_whitelist;
	int8_t			global_whitelist_use_l;
	int8_t			global_whitelist_use_m;

	char			*ecmfmt;
	char			*pidfile;

	int32_t			max_pending;

	// Ratelimit list
	struct s_rlimit	*ratelimit_list;

	// fake cws
	struct s_fakecws fakecws[0x100];

#ifdef MODULE_SERIAL
	struct s_twin	*twin_list;
#endif
};

struct s_clientinit
{
	void			*(*handler)(struct s_client *);
	struct s_client	*client;
};

struct s_clientmsg
{
	uint8_t			msg[1024];
	int32_t			len;
	int32_t			cmd;
};

typedef struct reader_stat_t
{
	int32_t			rc;
	uint16_t		caid;
	uint32_t		prid;
	uint16_t		srvid;
	uint32_t		chid;
	int16_t			ecmlen;

	struct timeb	last_received;

	int32_t			ecm_count;
	int32_t			time_avg;
	int32_t			time_stat[LB_MAX_STAT_TIME];
	int32_t			time_idx;

	int32_t			fail_factor;
} READER_STAT;

typedef struct cs_stat_query
{
	uint16_t		caid;
	uint32_t		prid;
	uint16_t		srvid;
	uint32_t		chid;
	int16_t			ecmlen;
} STAT_QUERY;

struct s_write_from_cache
{
	ECM_REQUEST		*er_new;
	ECM_REQUEST		*er_cache;
};

/* ===========================
 *		global variables
 * =========================== */
extern pthread_key_t getclient;
extern struct s_client *first_client;
extern CS_MUTEX_LOCK config_lock;
extern CS_MUTEX_LOCK clientlist_lock;
extern CS_MUTEX_LOCK readerlist_lock;
extern struct s_reader *first_active_reader;		// points to list of _active_ readers (enable = 1, deleted = 0)
extern LLIST *configured_readers;

// These are used pretty much everywhere
extern struct s_config cfg;
extern uint16_t cs_dblevel;

#include "oscam-log.h"
#include "oscam-log-reader.h"

// Add here *only* funcs that are implemented in oscam.c and are called in other places
void cs_exit(int32_t sig);
void cs_exit_oscam(void);
void cs_restart_oscam(void);
int32_t cs_get_restartmode(void);

void set_thread_name(const char *thread_name);
int32_t start_thread(char *nameroutine, void *startroutine, void *arg, pthread_t *pthread, int8_t detach, int8_t modify_stacksize);
int32_t start_thread_nolog(char *nameroutine, void *startroutine, void *arg, pthread_t *pthread, int8_t detach, int8_t modify_stacksize);
void kill_thread(struct s_client *cl);

struct s_module *get_module(struct s_client *cl);
void module_reader_set(struct s_reader *rdr);

// Until we find a better place for these (they are implemented in oscam-simples.h)
char *get_servicename(struct s_client *cl, uint16_t srvid, uint32_t provid, uint16_t caid, char *buf, uint32_t buflen);
char *get_servicename_or_null(struct s_client *cl, uint16_t srvid, uint32_t provid, uint16_t caid, char *buf, uint32_t buflen);
char *get_picon_servicename_or_null(struct s_client *cl, uint16_t srvid, uint32_t provid, uint16_t caid, char *buf, uint32_t buflen);
int32_t picon_servicename_remve_hd(char *buf, uint32_t buflen);
char *get_tiername(uint16_t tierid, uint16_t caid, char *buf);
char *get_tiername_defaultid(uint16_t tierid, uint16_t caid, char *buf);
char *get_provider(uint32_t provid, uint16_t caid, char *buf, uint32_t buflen);
char *get_providername(uint32_t provid, uint16_t caid, char *buf, uint32_t buflen);
char *get_providername_or_null(uint32_t provid, uint16_t caid, char *buf, uint32_t buflen);
void add_provider(uint16_t caid, uint32_t provid, const char *name, const char *sat, const char *lang);
const char *get_cl_lastprovidername(struct s_client *cl);
bool boxtype_is(const char *boxtype);
bool boxname_is(const char *boxname);
const char *boxtype_get(void);
const char *boxname_get(void);
static inline bool caid_is_fake(uint16_t caid) { return caid == 0xffff; }
static inline bool caid_is_biss(uint16_t caid) { return caid >> 8 == 0x26; }
static inline bool caid_is_biss_fixed(uint16_t caid) { return caid == 0x2600 || caid == 0x2602; } // fixed cw, fake ecm
static inline bool caid_is_biss_dynamic(uint16_t caid) { return caid == 0x2610; } // dynamic cw, real ecm and emm
static inline bool caid_is_seca(uint16_t caid) { return caid >> 8 == 0x01; }
static inline bool caid_is_viaccess(uint16_t caid) { return caid >> 8 == 0x05; }
static inline bool caid_is_irdeto(uint16_t caid) { return caid >> 8 == 0x06; }
static inline bool caid_is_videoguard(uint16_t caid) { return caid >> 8 == 0x09; }
static inline bool caid_is_conax(uint16_t caid) { return caid >> 8 == 0x0B; }
static inline bool caid_is_cryptoworks(uint16_t caid) { return caid >> 8 == 0x0D; }
static inline bool caid_is_powervu(uint16_t caid) { return caid >> 8 == 0x0E; }
static inline bool caid_is_director(uint16_t caid) { return caid >> 8 == 0x10; }
static inline bool caid_is_betacrypt(uint16_t caid) { return caid >> 8 == 0x17; }
static inline bool caid_is_nagra(uint16_t caid) { return caid >> 8 == 0x18; }
static inline bool caid_is_bulcrypt(uint16_t caid) { return caid == 0x5581 || caid == 0x4AEE; }
static inline bool caid_is_dre(uint16_t caid) { return caid == 0x4AE0 || caid == 0x4AE1 || caid == 0x2710;}
const char *get_cardsystem_desc_by_caid(uint16_t caid);

#ifdef WITH_EMU
FILTER *get_emu_prids_for_caid(struct s_reader *rdr, uint16_t caid);
#endif

#endif
