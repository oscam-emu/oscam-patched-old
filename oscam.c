#define MODULE_LOG_PREFIX "main"

#include "globals.h"
#include <getopt.h>

#include "csctapi/cardreaders.h"
#include "modules.h"
#include "readers.h"

#include "extapi/coolapi.h"
#include "module-anticasc.h"
#include "module-cacheex.h"
#include "module-cccam.h"
#include "module-dvbapi.h"
#include "module-dvbapi-azbox.h"
#include "module-dvbapi-mca.h"
#include "module-dvbapi-chancache.h"
#include "module-gbox-sms.h"
#include "module-ird-guess.h"
#include "module-lcd.h"
#include "module-led.h"
#include "module-stat.h"
#include "module-webif.h"
#include "module-webif-tpl.h"
#include "module-cw-cycle-check.h"
#include "oscam-chk.h"
#include "oscam-cache.h"
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-ecm.h"
#include "oscam-emm.h"
#include "oscam-emm-cache.h"
#include "oscam-files.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"
#include "reader-common.h"
#include "module-gbox.h"

#ifdef WITH_EMU
	void add_emu_reader(void);
	void stop_stream_server(void);
#endif

#ifdef WITH_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static void ssl_init(void)
{
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();
	SSL_library_init();
}

static void ssl_done(void)
{
#if OPENSSL_VERSION_NUMBER < 0x1010005fL
	ERR_remove_state(0);
#endif
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

#else
static void ssl_init(void) { }
static void ssl_done(void) { }
#endif

extern char *config_mak;

/*****************************************************************************
		Globals
*****************************************************************************/
const char *syslog_ident = "oscam";
static char *oscam_pidfile;
static char default_pidfile[64];

int32_t exit_oscam = 0;
static struct s_module modules[CS_MAX_MOD];

struct s_client *first_client = NULL; // Pointer to clients list, first client is master
struct s_reader *first_active_reader = NULL; // list of active readers (enable=1 deleted = 0)
LLIST *configured_readers = NULL; // list of all (configured) readers

uint16_t len4caid[256]; // table for guessing caid (by len)
char cs_confdir[128];
uint16_t cs_dblevel = 0; // Debug Level
int32_t thread_pipe[2] = {0, 0};
static int8_t cs_restart_mode = 1; // Restartmode: 0=off, no restart fork, 1=(default)restart fork, restart by webif, 2=like=1, but also restart on segfaults
#ifdef WITH_UTF8
uint8_t cs_http_use_utf8 = 1;
#else
uint8_t cs_http_use_utf8 = 0;
#endif
static int8_t cs_capture_SEGV;
static int8_t cs_dump_stack;
static uint16_t cs_waittime = 60;
char cs_tmpdir[200];
CS_MUTEX_LOCK system_lock;
CS_MUTEX_LOCK config_lock;
CS_MUTEX_LOCK gethostbyname_lock;
CS_MUTEX_LOCK clientlist_lock;
CS_MUTEX_LOCK readerlist_lock;
CS_MUTEX_LOCK fakeuser_lock;
CS_MUTEX_LOCK readdir_lock;
CS_MUTEX_LOCK cwcycle_lock;
pthread_key_t getclient;
static int32_t bg;
static int32_t gbdb;
static int32_t max_pending = 32;

// ecms list
CS_MUTEX_LOCK ecmcache_lock;
struct ecm_request_t *ecmcwcache = NULL;
uint32_t ecmcwcache_size = 0;

// pushout deleted list
CS_MUTEX_LOCK ecm_pushed_deleted_lock;
struct ecm_request_t *ecm_pushed_deleted = NULL;

struct s_config cfg;

int log_remove_sensitive = 1;

static char *prog_name;
static char *stb_boxtype;
static char *stb_boxname;

static int32_t oscam_stacksize = 0;

/*****************************************************************************
		Statics
*****************************************************************************/
/* Prints usage information and information about the built-in modules. */
static void show_usage(void)
{
	printf("%s",
		   "  ___  ____   ___\n"
		   " / _ \\/ ___| / __|__ _ _ __ ___\n"
		   "| | | \\___ \\| |  / _` | '_ ` _ \\\n"
		   "| |_| |___) | |_| (_| | | | | | |\n"
		   " \\___/|____/ \\___\\__,_|_| |_| |_|\n\n");
	printf("OSCam Cardserver v%s, build r%s (%s)\n", CS_VERSION, CS_SVN_VERSION, CS_TARGET);
	printf("Copyright (C) 2009-2020 OSCam developers.\n");
	printf("This program is distributed under GPLv3.\n");
	printf("OSCam is based on Streamboard mp-cardserver v0.9d written by dukat\n");
	printf("Visit https://board.streamboard.tv/ for more details.\n\n");

	printf(" ConfigDir  : %s\n", CS_CONFDIR);
	printf("\n");
	printf(" Usage: oscam [parameters]\n");
	printf("\n Directories:\n");
	printf(" -c, --config-dir <dir>  | Read configuration files from <dir>.\n");
	printf("                         . Default: %s\n", CS_CONFDIR);
	printf(" -t, --temp-dir <dir>    | Set temporary directory to <dir>.\n");
#if defined(__CYGWIN__)
	printf("                         . Default: (OS-TMP)\n");
#else
	printf("                         . Default: /tmp/.oscam\n");
#endif
	printf("\n Startup:\n");
#if defined(WITH_STAPI) || defined(WITH_STAPI5)
	printf(" -f, --foreground        | Start in the foreground mode.\n");
#else
	printf(" -b, --daemon            | Start in the background as daemon.\n");
#endif
	printf(" -B, --pidfile <pidfile> | Create pidfile when starting.\n");
	if(config_enabled(WEBIF))
	{
		printf(" -r, --restart <level>   | Set restart level:\n");
		printf("                         .   0 - Restart disabled (exit on restart request).\n");
		printf("                         .   1 - WebIf restart is active (default).\n");
		printf("                         .   2 - Like 1, but also restart on segfaults.\n");
	}
	printf(" -w, --wait <secs>       | Set how much seconds to wait at startup for the\n");
	printf("                         . system clock to be set correctly. Default: 60\n");
	printf("\n Logging:\n");
	printf(" -I, --syslog-ident <ident> | Set syslog ident. Default: oscam\n");
	printf(" -S, --show-sensitive    | Do not filter sensitive info (card serials, boxids)\n");
	printf("                         . from the logs.\n");
	printf(" -d, --debug <level>     | Set debug level mask used for logging:\n");
	printf("                         .     0 - No extra debugging (default).\n");
	printf("                         .     1 - Detailed error messages.\n");
	printf("                         .     2 - ATR parsing info, ECM, EMM and CW dumps.\n");
	printf("                         .     4 - Traffic from/to the reader.\n");
	printf("                         .     8 - Traffic from/to the clients.\n");
	printf("                         .    16 - Traffic to the reader-device on IFD layer.\n");
	printf("                         .    32 - Traffic to the reader-device on I/O layer.\n");
	printf("                         .    64 - EMM logging.\n");
	printf("                         .   128 - DVBAPI logging.\n");
	printf("                         .   256 - Loadbalancer logging.\n");
	printf("                         .   512 - CACHEEX logging.\n");
	printf("                         .  1024 - Client ECM logging.\n");
	printf("                         .  2048 - CSP logging.\n");
	printf("                         .  4096 - CWC logging.\n");
#ifdef CS_CACHEEX_AIO
	printf("                         .  8192 - CW Cache logging.\n");
#endif
	printf("                         . 65535 - Debug all.\n");
	printf("\n Settings:\n");
	printf(" -p, --pending-ecm <num> | Set the maximum number of pending ECM packets.\n");
	printf("                         . Default: 32 Max: 4096\n");
	if(config_enabled(WEBIF))
	{
		printf(" -u, --utf8              | Enable WebIf support for UTF-8 charset.\n");
	}
	printf("\n Debug parameters:\n");
	printf(" -a, --crash-dump        | Write oscam.crash file on segfault. This option\n");
	printf("                         . needs GDB to be installed and OSCam executable to\n");
	printf("                         . contain the debug information (run oscam-XXXX.debug)\n");
	printf(" -s, --capture-segfaults | Capture segmentation faults.\n");
	printf(" -g, --gcollect <mode>   | Garbage collector debug mode:\n");
	printf("                         .   1 - Immediate free.\n");
	printf("                         .   2 - Check for double frees.\n");
	printf("\n Information:\n");
	printf(" -h, --help              | Show command line help text.\n");
	printf(" -V, --build-info        | Show OSCam binary configuration and version.\n");
}

/* Keep the options sorted */
#if defined(WITH_STAPI) || defined(WITH_STAPI5)
static const char short_options[] = "aB:fc:d:g:hI:p:r:Sst:uVw:";
#else
static const char short_options[] = "aB:bc:d:g:hI:p:r:Sst:uVw:";
#endif

/* Keep the options sorted by short option */
static const struct option long_options[] =
{
	{ "crash-dump",         no_argument,       NULL, 'a' },
	{ "pidfile",            required_argument, NULL, 'B' },
#if defined(WITH_STAPI) || defined(WITH_STAPI5)
	{ "foreground",         no_argument,       NULL, 'f' },
#else
	{ "daemon",             no_argument,       NULL, 'b' },
#endif
	{ "config-dir",         required_argument, NULL, 'c' },
	{ "debug",              required_argument, NULL, 'd' },
	{ "gcollect",           required_argument, NULL, 'g' },
	{ "help",               no_argument,       NULL, 'h' },
	{ "syslog-ident",       required_argument, NULL, 'I' },
	{ "pending-ecm",        required_argument, NULL, 'p' },
	{ "restart",            required_argument, NULL, 'r' },
	{ "show-sensitive",     no_argument,       NULL, 'S' },
	{ "capture-segfaults",  no_argument,       NULL, 's' },
	{ "temp-dir",           required_argument, NULL, 't' },
	{ "utf8",               no_argument,       NULL, 'u' },
	{ "build-info",         no_argument,       NULL, 'V' },
	{ "wait",               required_argument, NULL, 'w' },
	{ 0, 0, 0, 0 }
};

static void set_default_dirs_first(void)
{
	snprintf(cs_confdir, sizeof(cs_confdir), "%s", CS_CONFDIR);
	memset(cs_tmpdir, 0, sizeof(cs_tmpdir)); // will get further procesed trought oscam_files.c !!
}

static void write_versionfile(bool use_stdout);

static void parse_cmdline_params(int argc, char **argv)
{
#if defined(WITH_STAPI) || defined(WITH_STAPI5)
	bg = 1;
#endif

	int i;
	while((i = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF)
	{
		if(i == '?')
			{ fprintf(stderr, "ERROR: Unknown command line parameter: %s\n", argv[optind - 1]); }
		switch(i)
		{
		case 'a': // --crash-dump
			cs_dump_stack = 1;
			break;
		case 'B': // --pidfile
			oscam_pidfile = optarg;
			break;
		case 'f': // --foreground
			bg = 0;
			break;
		case 'b': // --daemon
			bg = 1;
			break;
		case 'c': // --config-dir
			cs_strncpy(cs_confdir, optarg, sizeof(cs_confdir));
			break;
		case 'd': // --debug
			cs_dblevel = atoi(optarg);
			break;
		case 'g': // --gcollect
			gbdb = atoi(optarg);
			break;
		case 'h': // --help
			show_usage();
			exit(EXIT_SUCCESS);
			break;
		case 'I': // --syslog-ident
			syslog_ident = optarg;
			break;
		case 'p': // --pending-ecm
			max_pending = atoi(optarg) <= 0 ? 32 : MIN(atoi(optarg), 4096);
			break;
		case 'r': // --restart
			if(config_enabled(WEBIF))
			{
				cs_restart_mode = atoi(optarg);
			}
			break;
		case 'S': // --show-sensitive
			log_remove_sensitive = !log_remove_sensitive;
			break;
		case 's': // --capture-segfaults
			cs_capture_SEGV = 1;
			break;
		case 't':   // --temp-dir
		{
			mkdir(optarg, S_IRWXU);
			int j = open(optarg, O_RDONLY);
			if(j >= 0)
			{
				close(j);
				cs_strncpy(cs_tmpdir, optarg, sizeof(cs_tmpdir));
			}
			else
			{
				printf("WARNING: Temp dir does not exist. Using default value.\n");
			}
			break;
		}
		case 'u': // --utf8
			if(config_enabled(WEBIF))
			{
				cs_http_use_utf8 = 1;
				printf("WARNING: Web interface UTF-8 mode enabled. Carefully read documentation as bugs may arise.\n");
			}
			break;
		case 'V': // --build-info
			write_versionfile(true);
			exit(EXIT_SUCCESS);
			break;
		case 'w': // --wait
			cs_waittime = strtoul(optarg, NULL, 10);
			break;
		}
	}
}

#define write_conf(CONFIG_VAR, text) \
	fprintf(fp, "%-40s %s\n", text ":", config_enabled(CONFIG_VAR) ? "yes" : "no")

#define write_readerconf(CONFIG_VAR, text) \
	fprintf(fp, "%-40s %s\n", text ":", config_enabled(CONFIG_VAR) ? "yes" : "no - no EMM support!")

#define write_cardreaderconf(CONFIG_VAR, text) \
	fprintf(fp, "%s%-29s %s\n", "cardreader_", text ":", config_enabled(CONFIG_VAR) ? "yes" : "no")

static void write_versionfile(bool use_stdout)
{
	FILE *fp = stdout;
	if(!use_stdout)
	{
		char targetfile[256];
		fp = fopen(get_tmp_dir_filename(targetfile, sizeof(targetfile), "oscam.version"), "w");
		if(!fp)
		{
			cs_log("Cannot open %s (errno=%d %s)", targetfile, errno, strerror(errno));
			return;
		}
		struct tm st;
		time_t walltime = cs_time();
		localtime_r(&walltime, &st);
		fprintf(fp, "Unix starttime: %ld\n", walltime);
		fprintf(fp, "Starttime:      %02d.%02d.%04d %02d:%02d:%02d\n",
				st.tm_mday, st.tm_mon + 1, st.tm_year + 1900,
				st.tm_hour, st.tm_min, st.tm_sec);
	}

	fprintf(fp, "Version:        oscam-%s-r%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(fp, "Compiler:       %s\n", CS_TARGET);
	fprintf(fp, "Box type:       %s (%s)\n", boxtype_get(), boxname_get());
	fprintf(fp, "PID:            %d\n", getppid());
	fprintf(fp, "TempDir:        %s\n", cs_tmpdir);
#ifdef MODULE_GBOX
	if(cfg.gbox_tmp_dir == NULL)
	{
		fprintf(fp, "GBox tmp_dir:   not defined using: %s\n", cs_tmpdir);
	}
	else
	{
		fprintf(fp, "GBox tmp_dir:   %s\n", cfg.gbox_tmp_dir);
	}
#endif

	fprintf(fp, "ConfigDir:      %s\n", cs_confdir);

#ifdef WEBIF
	fprintf(fp, "WebifPort:      %d\n", cfg.http_port);
#endif

	fprintf(fp, "\n");
	write_conf(WEBIF, "Web interface support");
	write_conf(WEBIF_LIVELOG, "LiveLog support");
	write_conf(WEBIF_JQUERY, "jQuery support intern");
	write_conf(TOUCH, "Touch interface support");
	write_conf(WITH_SSL, "SSL support");
	write_conf(HAVE_DVBAPI, "DVB API support");
	if(config_enabled(HAVE_DVBAPI))
	{
		write_conf(WITH_AZBOX, "DVB API with AZBOX support");
		write_conf(WITH_MCA, "DVB API with MCA support");
		write_conf(WITH_COOLAPI, "DVB API with COOLAPI support");
		write_conf(WITH_COOLAPI2, "DVB API with COOLAPI2 support");
		write_conf(WITH_STAPI, "DVB API with STAPI support");
		write_conf(WITH_STAPI5, "DVB API with STAPI5 support");
		write_conf(WITH_NEUTRINO, "DVB API with NEUTRINO support");
		write_conf(READ_SDT_CHARSETS, "DVB API read-sdt charsets");
	}
	write_conf(IRDETO_GUESSING, "Irdeto guessing");
	write_conf(CS_ANTICASC, "Anti-cascading support");
	write_conf(WITH_DEBUG, "Debug mode");
	write_conf(MODULE_MONITOR, "Monitor");
	write_conf(WITH_LB, "Loadbalancing support");
	write_conf(CS_CACHEEX, "Cache exchange support");
#ifdef CS_CACHEEX_AIO
	write_conf(CS_CACHEEX_AIO, "Cache exchange AIO support");
#endif
	write_conf(CW_CYCLE_CHECK, "CW Cycle Check support");
	write_conf(LCDSUPPORT, "LCD support");
	write_conf(LEDSUPPORT, "LED support");
	switch (cs_getclocktype())
	{
		case CLOCK_TYPE_UNKNOWN  : write_conf(CLOCKFIX, "Clockfix with UNKNOWN clock"); break;
		case CLOCK_TYPE_REALTIME : write_conf(CLOCKFIX, "Clockfix with realtime clock"); break;
		case CLOCK_TYPE_MONOTONIC: write_conf(CLOCKFIX, "Clockfix with monotonic clock"); break;
	}
	write_conf(IPV6SUPPORT, "IPv6 support");
	write_conf(WITH_EMU, "Emulator support");
	write_conf(WITH_SOFTCAM, "Built-in SoftCam.Key");

	fprintf(fp, "\n");
	write_conf(MODULE_CAMD33, "camd 3.3x");
	write_conf(MODULE_CAMD35, "camd 3.5 UDP");
	write_conf(MODULE_CAMD35_TCP, "camd 3.5 TCP");
	write_conf(MODULE_NEWCAMD, "newcamd");
	write_conf(MODULE_CCCAM, "CCcam");
	write_conf(MODULE_CCCSHARE, "CCcam share");
	write_conf(MODULE_GBOX, "gbox");
	write_conf(MODULE_RADEGAST, "radegast");
	write_conf(MODULE_SCAM, "scam");
	write_conf(MODULE_SERIAL, "serial");
	write_conf(MODULE_CONSTCW, "constant CW");
	write_conf(MODULE_PANDORA, "Pandora");
	write_conf(MODULE_GHTTP, "ghttp");

	fprintf(fp, "\n");
	write_conf(WITH_CARDREADER, "Reader support");
	if(config_enabled(WITH_CARDREADER))
	{
		fprintf(fp, "\n");
		write_readerconf(READER_NAGRA, "Nagra");
		write_readerconf(READER_NAGRA_MERLIN, "Nagra Merlin");
		write_readerconf(READER_IRDETO, "Irdeto");
		write_readerconf(READER_CONAX, "Conax");
		write_readerconf(READER_CRYPTOWORKS, "Cryptoworks");
		write_readerconf(READER_SECA, "Seca");
		write_readerconf(READER_VIACCESS, "Viaccess");
		write_readerconf(READER_VIDEOGUARD, "NDS Videoguard");
		write_readerconf(READER_DRE, "DRE Crypt");
		write_readerconf(READER_TONGFANG, "TONGFANG");
		write_readerconf(READER_BULCRYPT, "Bulcrypt");
		write_readerconf(READER_GRIFFIN, "Griffin");
		write_readerconf(READER_DGCRYPT, "DGCrypt");
		fprintf(fp, "\n");
		write_cardreaderconf(CARDREADER_PHOENIX, "phoenix");
		write_cardreaderconf(CARDREADER_DRECAS, "drecas");
		write_cardreaderconf(CARDREADER_INTERNAL_AZBOX, "internal_azbox");
		write_cardreaderconf(CARDREADER_INTERNAL_COOLAPI, "internal_coolapi");
		write_cardreaderconf(CARDREADER_INTERNAL_COOLAPI2, "internal_coolapi2");
		write_cardreaderconf(CARDREADER_INTERNAL_SCI, "internal_sci");
		write_cardreaderconf(CARDREADER_SC8IN1, "sc8in1");
		write_cardreaderconf(CARDREADER_MP35, "mp35");
		write_cardreaderconf(CARDREADER_SMARGO, "smargo");
		write_cardreaderconf(CARDREADER_PCSC, "pcsc");
		write_cardreaderconf(CARDREADER_SMART, "smartreader");
		write_cardreaderconf(CARDREADER_DB2COM, "db2com");
		write_cardreaderconf(CARDREADER_STAPI, "stapi");
		write_cardreaderconf(CARDREADER_STAPI5, "stapi5");
		write_cardreaderconf(CARDREADER_STINGER, "stinger");
	}
	else
	{
		write_readerconf(WITH_CARDREADER, "Reader Support");
	}
	if(!use_stdout)
		{ fclose(fp); }
}
#undef write_conf
#undef write_readerconf
#undef write_cardreaderconf

static void remove_versionfile(void)
{
	char targetfile[256];
	unlink(get_tmp_dir_filename(targetfile, sizeof(targetfile), "oscam.version"));
}

#define report_emm_support(CONFIG_VAR, text) \
	do { \
		if (!config_enabled(CONFIG_VAR)) \
			cs_log_dbg(D_TRACE, "Binary without %s module - no EMM processing for %s possible!", text, text); \
	} while(0)

static void do_report_emm_support(void)
{
	if(!config_enabled(WITH_CARDREADER))
	{
		cs_log("Binary without Cardreader Support! No EMM processing possible!");
	}
	else
	{
		report_emm_support(READER_NAGRA, "Nagra");
		report_emm_support(READER_NAGRA_MERLIN, "Nagra Merlin");
		report_emm_support(READER_IRDETO, "Irdeto");
		report_emm_support(READER_CONAX, "Conax");
		report_emm_support(READER_CRYPTOWORKS, "Cryptoworks");
		report_emm_support(READER_SECA, "Seca");
		report_emm_support(READER_VIACCESS, "Viaccess");
		report_emm_support(READER_VIDEOGUARD, "NDS Videoguard");
		report_emm_support(READER_DRE, "DRE Crypt");
		report_emm_support(READER_TONGFANG, "TONGFANG");
		report_emm_support(READER_BULCRYPT, "Bulcrypt");
		report_emm_support(READER_GRIFFIN, "Griffin");
		report_emm_support(READER_DGCRYPT, "DGCrypt");
	}
}
#undef report_emm_support

#ifdef NEED_DAEMON
// The compat function is not called daemon() because this may cause problems.
static int32_t do_daemon(int32_t nochdir, int32_t noclose)
{
	int32_t fd;

	switch(fork())
	{
	case -1:
		return (-1);
	case 0:
		break;
	default:
		_exit(0);
	}

	if(setsid() == (-1))
		{ return (-1); }

	if(!nochdir)
		{ (void)chdir("/"); }

	if(!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1)
	{
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if(fd > 2)
			{ (void)close(fd); }
	}
	return (0);
}
#else
#define do_daemon daemon
#endif

/*
 * flags: 1 = restart, 2 = don't modify if SIG_IGN, may be combined
 */
static void set_signal_handler(int32_t sig, int32_t flags, void (*sighandler))
{
	struct sigaction sa;
	sigaction(sig, (struct sigaction *) 0, &sa);
	if(!((flags & 2) && (sa.sa_handler == SIG_IGN)))
	{
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = (flags & 1) ? SA_RESTART : 0;
		sa.sa_handler = sighandler;
		sigaction(sig, &sa, (struct sigaction *) 0);
	}
}

static void cs_master_alarm(void)
{
	cs_log("PANIC: master deadlock!");
	fprintf(stderr, "PANIC: master deadlock!");
	fflush(stderr);
}

static void cs_sigpipe(void)
{
	if(cs_dblevel & D_ALL_DUMP)
		{ cs_log("Got sigpipe signal -> captured"); }
}

static void cs_dummy(void)
{
	return;
}

/* Switch debuglevel forward one step (called when receiving SIGUSR1). */
static void cs_debug_level(void)
{
	switch(cs_dblevel)
	{
	case 0:
		cs_dblevel = 1;
		break;
	case 128:
		cs_dblevel = 255;
		break;
	case 255:
		cs_dblevel = 0;
		break;
	default:
		cs_dblevel <<= 1;
	}

	cs_log("debug_level=%d", cs_dblevel);
}

/**
 * write stacktrace to oscam.crash. file is always appended
 * Usage:
 * 1. compile oscam with debug parameters (Makefile: DS_OPTS="-ggdb")
 * 2. you need gdb installed and working on the local machine
 * 3. start oscam with parameter: -a
 */
static void cs_dumpstack(int32_t sig)
{
	FILE *fp = fopen("oscam.crash", "a+");

	time_t timep;
	char buf[200];

	time(&timep);
	cs_ctime_r(&timep, buf);

	fprintf(stderr, "crashed with signal %d on %swriting oscam.crash\n", sig, buf);

	fprintf(fp, "%sOSCam cardserver v%s, build r%s (%s)\n", buf, CS_VERSION, CS_SVN_VERSION, CS_TARGET);
	fprintf(fp, "FATAL: Signal %d: %s Fault. Logged StackTrace:\n\n", sig, (sig == SIGSEGV) ? "Segmentation" : ((sig == SIGBUS) ? "Bus" : "Unknown"));
	fclose(fp);

	FILE *cmd = fopen("/tmp/gdbcmd", "w");
	fputs("bt\n", cmd);
	fputs("thread apply all bt\n", cmd);
	fclose(cmd);

	snprintf(buf, sizeof(buf) - 1, "gdb %s %d -batch -x /tmp/gdbcmd >> oscam.crash", prog_name, getpid());
	if(system(buf) == -1)
		{ fprintf(stderr, "Fatal error on trying to start gdb process."); }

	exit(-1);
}


/**
 * called by signal SIGHUP
 *
 * reloads configs:
 *  - useraccounts (oscam.user)
 *  - readers      (oscam.server)
 *  - services ids (oscam.srvid)
 *  - tier ids     (oscam.tiers)
 *  Also clears anticascading stats.
 **/
static void cs_reload_config(void)
{
	static pthread_mutex_t mutex;
	static int8_t mutex_init = 0;

	if(!mutex_init)
	{
		SAFE_MUTEX_INIT(&mutex, NULL);
		mutex_init = 1;
	}

	if(pthread_mutex_trylock(&mutex))
	{
		return;
	}

	if(cfg.reload_useraccounts)
	{
		cs_accounts_chk();
	}

	if(cfg.reload_readers)
	{
		reload_readerdb();
	}

	if(cfg.reload_provid)
	{
		init_provid();
	}

	if(cfg.reload_services_ids)
	{
		init_srvid();
	}

	if(cfg.reload_tier_ids)
	{
		init_tierid();
	}

	if(cfg.reload_fakecws)
	{
		init_fakecws();
	}

	if(cfg.reload_ac_stat)
	{
		ac_init_stat();
	}

	if(cfg.reload_log)
	{
		cs_reopen_log(); // FIXME: aclog.log, emm logs, cw logs (?)
	}

	SAFE_MUTEX_UNLOCK(&mutex);
}

/* Sets signal handlers to ignore for early startup of OSCam because for example log
   could cause SIGPIPE errors and the normal signal handlers can't be used at this point. */
static void init_signal_pre(void)
{
	set_signal_handler(SIGPIPE , 1, SIG_IGN);
	set_signal_handler(SIGWINCH, 1, SIG_IGN);
	set_signal_handler(SIGALRM , 1, SIG_IGN);
	set_signal_handler(SIGHUP  , 1, SIG_IGN);
}

/* Sets the signal handlers.*/
static void init_signal(void)
{
	set_signal_handler(SIGINT, 3, cs_exit);
#if defined(__APPLE__)
	set_signal_handler(SIGEMT, 3, cs_exit);
#endif
	set_signal_handler(SIGTERM, 3, cs_exit);

	set_signal_handler(SIGWINCH, 1, SIG_IGN);
	set_signal_handler(SIGPIPE, 0, cs_sigpipe);
	set_signal_handler(SIGALRM, 0, cs_master_alarm);
	set_signal_handler(SIGHUP, 1, cs_reload_config);
	set_signal_handler(SIGUSR1, 1, cs_debug_level);
	set_signal_handler(SIGUSR2, 1, cs_card_info);
	set_signal_handler(OSCAM_SIGNAL_WAKEUP, 0, cs_dummy);

	if(cs_capture_SEGV)
	{
		set_signal_handler(SIGSEGV, 1, cs_exit);
		set_signal_handler(SIGBUS, 1, cs_exit);
	}
	else if(cs_dump_stack)
	{
		set_signal_handler(SIGSEGV, 1, cs_dumpstack);
		set_signal_handler(SIGBUS, 1, cs_dumpstack);
	}

	cs_log("signal handling initialized");
	return;
}

void cs_exit(int32_t sig)
{
	if(cs_dump_stack && (sig == SIGSEGV || sig == SIGBUS || sig == SIGQUIT))
		{ cs_dumpstack(sig); }

	set_signal_handler(SIGHUP , 1, SIG_IGN);
	set_signal_handler(SIGPIPE, 1, SIG_IGN);

	struct s_client *cl = cur_client();
	if(!cl)
		{ return; }

	// this is very important - do not remove
	if(cl->typ != 's')
	{
		cs_log_dbg(D_TRACE, "thread %8lX ended!", (unsigned long)pthread_self());

		free_client(cl);

		// Restore signals before exiting thread
		set_signal_handler(SIGPIPE, 0, cs_sigpipe);
		set_signal_handler(SIGHUP, 1, cs_reload_config);

		pthread_exit(NULL);
		return;
	}

	if(!exit_oscam)
		{ exit_oscam = sig ? sig : 1; }
}

static char *read_line_from_file(char *fname, char *buf, int bufsz)
{
	memset(buf, 0, bufsz);
	FILE *f = fopen(fname, "r");
	if (!f)
		return NULL;
	while (fgets(buf, bufsz, f))
	{
		if (strstr(buf,"\n")) // we need only the first line
		{
			buf[cs_strlen(buf)-1] = '\0';
			break;
		}
	}
	fclose(f);
	if (buf[0])
		return buf;
	return NULL;
}

static void init_machine_info(void)
{
	struct utsname buffer;
	if (uname(&buffer) == 0)
	{
		cs_log("System name    = %s", buffer.sysname);
		cs_log("Host name      = %s", buffer.nodename);
		cs_log("Release        = %s", buffer.release);
		cs_log("Version        = %s", buffer.version);
		cs_log("Machine        = %s", buffer.machine);
	} else {
		cs_log("ERROR: uname call failed: %s", strerror(errno));
	}

#if !defined(__linux__)
	return;
#endif

	// Linux only functionality
	char boxtype[128];
	boxtype[0] = 0;
	char model[64];
	model[0] = 0;
	char vumodel[64];
	vumodel[0] = 0;
	int8_t azmodel = 0;
	FILE *f;

	if ((f = fopen("/proc/stb/info/azmodel", "r"))){ azmodel = 1; fclose(f);}
	read_line_from_file("/proc/stb/info/model", model, sizeof(model));
	read_line_from_file("/proc/stb/info/boxtype", boxtype, sizeof(boxtype));
	read_line_from_file("/proc/stb/info/vumodel", vumodel, sizeof(vumodel));
	if (vumodel[0] && !boxtype[0] && !azmodel)
	{
		snprintf(boxtype, sizeof(boxtype), "vu%s", vumodel);
	}
	if (!boxtype[0] && azmodel)
		snprintf(boxtype, sizeof(boxtype), "Azbox-%s", model);

	// Detect dreambox type
	if (strcasecmp(buffer.machine, "ppc") == 0 && !model[0] && !boxtype[0])
	{
		char line[128], *p;
		int have_dreambox = 0;
		if ((f = fopen("/proc/cpuinfo", "r")))
		{
			while (fgets(line, sizeof(line), f))
			{
				if (strstr(line, "STBx25xx")) have_dreambox++;
				if (strstr(line, "pvr"     )) have_dreambox++;
				if (strstr(line, "Dreambox")) have_dreambox++;
				if (strstr(line, "9.80"    )) have_dreambox++;
				if (strstr(line, "63MHz"   )) have_dreambox++;
			}
			fclose(f);
			have_dreambox = have_dreambox == 5 ? 1 : 0; // Need to find all 5 strings
		}
		if (have_dreambox)
		{
			if (read_line_from_file("/proc/meminfo", line, sizeof(line)) && (p = strchr(line, ' ')))
			{
				unsigned long memtotal = strtoul(p, NULL, 10);
				if (memtotal > 40000)
					snprintf(boxtype, sizeof(boxtype), "%s", "dm600pvr");
				else
					snprintf(boxtype, sizeof(boxtype), "%s", "dm500");
			}
		}
	}

	if (!boxtype[0] && !strcasecmp(model, "dm800") && !strcasecmp(buffer.machine, "armv7l"))
		snprintf(boxtype, sizeof(boxtype), "%s", "su980");

	if (!boxtype[0])
	{
		uint8_t *pos;
		pos = (uint8_t *)memchr(buffer.release, 'd', sizeof(buffer.release));
		if(pos)
		{
			if((!memcmp(pos, "dbox2", sizeof("dbox2"))) && !strcasecmp(buffer.machine, "ppc"))
			{
				snprintf(boxtype, sizeof(boxtype), "%s", "dbox2");
			}
		}
	}

	if (model[0])
		cs_log("Stb model      = %s", model);

	if (vumodel[0])
		cs_log("Stb vumodel    = vu%s", vumodel);

	if (boxtype[0])
	{
		char boxname[128];
		if(!strcasecmp(boxtype,"ini-8000am")){snprintf(boxname, sizeof(boxname), "%s", "Atemio Nemesis");}
		else if(!strcasecmp(boxtype,"ini-9000ru")){snprintf(boxname, sizeof(boxname), "%s", "Sezam Marvel");}
		else if(!strcasecmp(boxtype,"ini-8000sv")){snprintf(boxname, sizeof(boxname), "%s", "Miraclebox Ultra");}
		else if(!strcasecmp(boxtype,"ini-9000de")){snprintf(boxname, sizeof(boxname), "%s", "Xpeed LX3");}
		else boxname[0] = 0;
		if(boxname[0]){cs_log("Stb boxname    = %s", boxname); stb_boxname = cs_strdup(boxname);}
		cs_log("Stb boxtype    = %s", boxtype);
	}

	if (boxtype[0])
		stb_boxtype = cs_strdup(boxtype);
	else if (model[0])
		stb_boxtype = cs_strdup(model);
}

const char *boxtype_get(void)
{
	return stb_boxtype ? stb_boxtype : "generic";
}

const char *boxname_get(void)
{
	return stb_boxname ? stb_boxname : "generic";
}

bool boxtype_is(const char *boxtype)
{
	return strcasecmp(boxtype_get(), boxtype) == 0;
}

bool boxname_is(const char *boxname)
{
	return strcasecmp(boxname_get(), boxname) == 0;
}

/* Checks if the date of the system is correct and waits if necessary. */
static void init_check(void)
{
	char *ptr = __DATE__;
	int32_t month, year = atoi(ptr + cs_strlen(ptr) - 4), day = atoi(ptr + 4);
	if(day > 0 && day < 32 && year > 2010 && year < 9999)
	{
		struct tm timeinfo;
		char months[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
		for(month = 0; month < 12; ++month)
		{
			if(!strncmp(ptr, months[month], 3)) { break; }
		}
		if(month > 11) { month = 0; }
		memset(&timeinfo, 0, sizeof(timeinfo));
		timeinfo.tm_mday = day;
		timeinfo.tm_mon = month;
		timeinfo.tm_year = year - 1900;
		time_t builddate = mktime(&timeinfo) - 86400;
		int32_t i = 0;
		while(time((time_t *)0) < builddate)
		{
			if(i == 0) { cs_log("The current system time is smaller than the build date (%s). Waiting up to %d seconds for time to correct", ptr, cs_waittime); }
			cs_sleepms(1000);
			++i;
			if(i > cs_waittime)
			{
				cs_log("Waiting was not successful. OSCam will be started but is UNSUPPORTED this way. Do not report any errors with this version.");
				break;
			}
		}
		// adjust login time of first client
		if(i > 0) { first_client->login = time((time_t *)0); }
	}
}

#ifdef __linux__
#include <sys/prctl.h>
// PR_SET_NAME is introduced in 2.6.9 (which is ancient, released 18 Oct 2004)
// but apparantly we can't count on having at least that version :(
#ifndef PR_SET_NAME
#define PR_SET_NAME    15
#endif
// Set the thread name (comm) under linux (the limit is 16 chars)
void set_thread_name(const char *thread_name)
{
	prctl(PR_SET_NAME, thread_name, NULL, NULL, NULL);
}
#else
void set_thread_name(const char *UNUSED(thread_name)) { }
#endif


static void fix_stacksize(void)
{
// Changing the default stack size is generally a bad idea.
// We are doing it anyway at the moment, because we are using several threads,
// and are running on machnies with little RAM.
// HOWEVER, as we do not know which minimal stack size is needed to run
// oscam without SEQFAULT (stack overflow), this is risky business.
// If after a code change SEQFAULTs related to stack overflow appear,
// increase OSCAM_STACK_MIN or remove the calls to SAFE_ATTR_SETSTACKSIZE.

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 64000
#endif
#define OSCAM_STACK_MIN PTHREAD_STACK_MIN + 32768

	if(oscam_stacksize < OSCAM_STACK_MIN)
	{
		long pagesize = sysconf(_SC_PAGESIZE);
		if(pagesize < 1)
		{
			oscam_stacksize = OSCAM_STACK_MIN;
			return;
		}

		oscam_stacksize = ((OSCAM_STACK_MIN) / pagesize + 1) * pagesize;
	}
}

/* Starts a thread named nameroutine with the start function startroutine. */
int32_t start_thread(char *nameroutine, void *startroutine, void *arg, pthread_t *pthread, int8_t detach, int8_t modify_stacksize)
{
	pthread_t temp;
	pthread_attr_t attr;

	cs_log_dbg(D_TRACE, "starting thread %s", nameroutine);

	SAFE_ATTR_INIT(&attr);

	if(modify_stacksize)
		{ SAFE_ATTR_SETSTACKSIZE(&attr, oscam_stacksize); }

	int32_t ret = pthread_create(pthread == NULL ? &temp : pthread, &attr, startroutine, arg);
	if(ret)
		{ cs_log("ERROR: can't create %s thread (errno=%d %s)", nameroutine, ret, strerror(ret)); }
	else
	{
		cs_log_dbg(D_TRACE, "%s thread started", nameroutine);

		if(detach)
			{ pthread_detach(pthread == NULL ? temp : *pthread); }
	}

	pthread_attr_destroy(&attr);

	return ret;
}

int32_t start_thread_nolog(char *nameroutine, void *startroutine, void *arg, pthread_t *pthread, int8_t detach, int8_t modify_stacksize)
{
	pthread_t temp;
	pthread_attr_t attr;

	SAFE_ATTR_INIT(&attr);

	if(modify_stacksize)
 		{ SAFE_ATTR_SETSTACKSIZE(&attr, oscam_stacksize); }

	int32_t ret = pthread_create(pthread == NULL ? &temp : pthread, &attr, startroutine, arg);
	if(ret)
		{ fprintf(stderr, "ERROR: can't create %s thread (errno=%d %s)", nameroutine, ret, strerror(ret)); }
	else
	{
		if(detach)
			{ pthread_detach(pthread == NULL ? temp : *pthread); }
	}

	pthread_attr_destroy(&attr);

	return ret;
}

/* Allows to kill another thread specified through the client cl with locking.
  If the own thread has to be cancelled, cs_exit or cs_disconnect_client has to be used. */
void kill_thread(struct s_client *cl)
{
	if(!cl || cl->kill) { return; }
	if(cl == cur_client())
	{
		cs_log("Trying to kill myself, exiting.");
		cs_exit(0);
	}
	add_job(cl, ACTION_CLIENT_KILL, NULL, 0); //add kill job, ...
	cl->kill = 1;                             //then set kill flag!
}

struct s_module *get_module(struct s_client *cl)
{
	return &modules[cl->module_idx];
}

void module_reader_set(struct s_reader *rdr)
{
	int i;
	if(!is_cascading_reader(rdr))
		{ return; }
	for(i = 0; i < CS_MAX_MOD; i++)
	{
		struct s_module *module = &modules[i];
		if(module->num && module->num == rdr->typ)
			rdr->ph = *module;
	}
}

static void cs_waitforcardinit(void)
{
	if(cfg.waitforcards)
	{
		cs_log("waiting for local card init");
		int32_t card_init_done;
		do
		{
			card_init_done = 1;
			struct s_reader *rdr;
			LL_ITER itr = ll_iter_create(configured_readers);
			while((rdr = ll_iter_next(&itr)))
			{
				if(rdr->enable && !is_cascading_reader(rdr) && (rdr->card_status == CARD_NEED_INIT || rdr->card_status == UNKNOWN))
				{
					card_init_done = 0;
					break;
				}
			}

			if(!card_init_done)
				{ cs_sleepms(300); } // wait a little bit
			//alarm(cfg.cmaxidle + cfg.ctimeout / 1000 + 1);
		}
		while(!card_init_done && !exit_oscam);

		if(cfg.waitforcards_extra_delay > 0 && !exit_oscam)
			{ cs_sleepms(cfg.waitforcards_extra_delay); }
		cs_log("init for all local cards done");
	}
}

static uint32_t resize_pfd_cllist(struct pollfd **pfd, struct s_client ***cl_list, uint32_t old_size, uint32_t new_size)
{
	if(old_size != new_size)
	{
		struct pollfd *pfd_new;
		if(!cs_malloc(&pfd_new, new_size * sizeof(struct pollfd)))
		{
			return old_size;
		}
		struct s_client **cl_list_new;
		if(!cs_malloc(&cl_list_new, new_size * sizeof(cl_list)))
		{
			NULLFREE(pfd_new);
			return old_size;
		}
		if(old_size > 0)
		{
			memcpy(pfd_new, *pfd, old_size * sizeof(struct pollfd));
			memcpy(cl_list_new, *cl_list, old_size * sizeof(cl_list));
			NULLFREE(*pfd);
			NULLFREE(*cl_list);
		}
		*pfd = pfd_new;
		*cl_list = cl_list_new;
	}
	return new_size;
}

static uint32_t chk_resize_cllist(struct pollfd **pfd, struct s_client ***cl_list, uint32_t cur_size, uint32_t chk_size)
{
	chk_size++;
	if(chk_size > cur_size)
	{
		uint32_t new_size = ((chk_size % 100) + 1) * 100; //increase 100 step
		cur_size = resize_pfd_cllist(pfd, cl_list, cur_size, new_size);
	}
	return cur_size;
}

static void process_clients(void)
{
	int32_t i, k, j, rc, pfdcount = 0;
	struct s_client *cl;
	struct s_reader *rdr;
	struct pollfd *pfd;
	struct s_client **cl_list;
	struct timeb start, end; // start time poll, end time poll
	uint32_t cl_size = 0;

	uint8_t buf[10];

	if(pipe(thread_pipe) == -1)
	{
		printf("cannot create pipe, errno=%d\n", errno);
		exit(1);
	}

	cl_size = chk_resize_cllist(&pfd, &cl_list, 0, 100);

	pfd[pfdcount].fd = thread_pipe[0];
	pfd[pfdcount].events = POLLIN | POLLPRI;
	cl_list[pfdcount] = NULL;

	while(!exit_oscam)
	{
		pfdcount = 1;

		// connected tcp clients
		for(cl = first_client->next; cl; cl = cl->next)
		{
			if(cl->init_done && !cl->kill && cl->pfd && cl->typ == 'c' && !cl->is_udp)
			{
				if(cl->pfd && !cl->thread_active)
				{
					cl_size = chk_resize_cllist(&pfd, &cl_list, cl_size, pfdcount);
					cl_list[pfdcount] = cl;
					pfd[pfdcount].fd = cl->pfd;
					pfd[pfdcount++].events = POLLIN | POLLPRI;
				}
			}
			//reader:
			//TCP:
			//  - TCP socket must be connected
			//  - no active init thread
			//UDP:
			//  - connection status ignored
			//  - no active init thread
			rdr = cl->reader;
			if(rdr && cl->typ == 'p' && cl->init_done)
			{
				if(cl->pfd && !cl->thread_active && ((rdr->tcp_connected && rdr->ph.type == MOD_CONN_TCP) || (rdr->ph.type == MOD_CONN_UDP)))
				{
					cl_size = chk_resize_cllist(&pfd, &cl_list, cl_size, pfdcount);
					cl_list[pfdcount] = cl;
					pfd[pfdcount].fd = cl->pfd;
					pfd[pfdcount++].events = (POLLIN | POLLPRI);
				}
			}
		}

		//server (new tcp connections or udp messages)
		for(k = 0; k < CS_MAX_MOD; k++)
		{
			struct s_module *module = &modules[k];
			if((module->type & MOD_CONN_NET))
			{
				for(j = 0; j < module->ptab.nports; j++)
				{
					if(module->ptab.ports[j].fd)
					{
						cl_size = chk_resize_cllist(&pfd, &cl_list, cl_size, pfdcount);
						cl_list[pfdcount] = NULL;
						pfd[pfdcount].fd = module->ptab.ports[j].fd;
						pfd[pfdcount++].events = (POLLIN | POLLPRI);
					}
				}
			}
		}

		if(pfdcount >= 1024)
			{ cs_log("WARNING: too many users!"); }
		cs_ftime(&start); // register start time
		rc = poll(pfd, pfdcount, 5000);
		if(rc < 1) { continue; }
		cs_ftime(&end); // register end time

		for(i = 0; i < pfdcount && rc > 0; i++)
		{
			if(pfd[i].revents == 0) { continue; }  // skip sockets with no changes
			rc--; //event handled!
			cs_log_dbg(D_TRACE, "[OSCAM] new event %d occurred on fd %d after %"PRId64" ms inactivity", pfd[i].revents,
						  pfd[i].fd, comp_timeb(&end, &start));
			//clients
			cl = cl_list[i];
			if(cl && !is_valid_client(cl))
				{ continue; }

			if(pfd[i].fd == thread_pipe[0] && (pfd[i].revents & (POLLIN | POLLPRI)))
			{
				// a thread ended and cl->pfd should be added to pollfd list again (thread_active==0)
				int32_t len = read(thread_pipe[0], buf, sizeof(buf));
				if(len == -1)
				{
					cs_log_dbg(D_TRACE, "[OSCAM] Reading from pipe failed (errno=%d %s)", errno, strerror(errno));
				}
				cs_log_dump_dbg(D_TRACE, buf, len, "[OSCAM] Readed:");
				continue;
			}

			//clients
			// message on an open tcp connection
			if(cl && cl->init_done && cl->pfd && (cl->typ == 'c' || cl->typ == 'm'))
			{
				if(pfd[i].fd == cl->pfd && (pfd[i].revents & (POLLHUP | POLLNVAL | POLLERR)))
				{
					//client disconnects
					kill_thread(cl);
					continue;
				}
				if(pfd[i].fd == cl->pfd && (pfd[i].revents & (POLLIN | POLLPRI)))
				{
					add_job(cl, ACTION_CLIENT_TCP, NULL, 0);
				}
			}

			//reader
			// either an ecm answer, a keepalive or connection closed from a proxy
			// physical reader ('r') should never send data without request
			rdr = NULL;
			struct s_client *cl2 = NULL;
			if(cl && cl->typ == 'p')
			{
				rdr = cl->reader;
				if(rdr)
					{ cl2 = rdr->client; }
			}

			if(rdr && cl2 && cl2->init_done)
			{
				if(cl2->pfd && pfd[i].fd == cl2->pfd && (pfd[i].revents & (POLLHUP | POLLNVAL | POLLERR)))
				{
					//connection to remote proxy was closed
					//oscam should check for rdr->tcp_connected and reconnect on next ecm request sent to the proxy
					network_tcp_connection_close(rdr, "closed");
					rdr_log_dbg(rdr, D_READER, "connection closed");
				}
				if(cl2->pfd && pfd[i].fd == cl2->pfd && (pfd[i].revents & (POLLIN | POLLPRI)))
				{
					add_job(cl2, ACTION_READER_REMOTE, NULL, 0);
				}
			}

			//server sockets
			// new connection on a tcp listen socket or new message on udp listen socket
			if(!cl && (pfd[i].revents & (POLLIN | POLLPRI)))
			{
				for(k = 0; k < CS_MAX_MOD; k++)
				{
					struct s_module *module = &modules[k];
					if((module->type & MOD_CONN_NET))
					{
						for(j = 0; j < module->ptab.nports; j++)
						{
							if(module->ptab.ports[j].fd && module->ptab.ports[j].fd == pfd[i].fd)
							{
								accept_connection(module, k, j);
							}
						}
					}
				}
			}
		}
		cs_ftime(&start); // register start time for new poll next run
		first_client->last = time((time_t *)0);
	}
	NULLFREE(pfd);
	NULLFREE(cl_list);
	return;
}

static pthread_cond_t reader_check_sleep_cond;
static pthread_mutex_t reader_check_sleep_cond_mutex;

static void *reader_check(void)
{
	struct s_client *cl;
	struct s_reader *rdr;
	set_thread_name(__func__);
	cs_pthread_cond_init(__func__, &reader_check_sleep_cond_mutex, &reader_check_sleep_cond);
	while(!exit_oscam)
	{
		for(cl = first_client->next; cl ; cl = cl->next)
		{
			if(!cl->thread_active)
				{ client_check_status(cl); }
		}
		cs_readlock(__func__, &readerlist_lock);
		for(rdr = first_active_reader; rdr; rdr = rdr->next)
		{
			if(rdr->enable)
			{
				cl = rdr->client;
				if(!cl || cl->kill)
					{ restart_cardreader(rdr, 0); }
				else if(!cl->thread_active)
					{ client_check_status(cl); }
			}
		}
		cs_readunlock(__func__, &readerlist_lock);
		sleepms_on_cond(__func__, &reader_check_sleep_cond_mutex, &reader_check_sleep_cond, 1000);
	}
	return NULL;
}

static pthread_cond_t card_poll_sleep_cond;

static void * card_poll(void) {
	struct s_client *cl;
	struct s_reader *rdr;
	pthread_mutex_t card_poll_sleep_cond_mutex;
	SAFE_MUTEX_INIT(&card_poll_sleep_cond_mutex, NULL);
	SAFE_COND_INIT(&card_poll_sleep_cond, NULL);
	set_thread_name(__func__);
	while (!exit_oscam) {
		cs_readlock(__func__, &readerlist_lock);
		for (rdr=first_active_reader; rdr; rdr=rdr->next) {
			if (rdr->enable && rdr->card_status == CARD_INSERTED) {
				cl = rdr->client;
				if (cl && !cl->kill)
					{ add_job(cl, ACTION_READER_POLL_STATUS, 0, 0); }
			}
		}
		cs_readunlock(__func__, &readerlist_lock);
		struct timespec ts;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec * 1000;
		ts.tv_sec += 1;
		SAFE_MUTEX_LOCK(&card_poll_sleep_cond_mutex);
		SAFE_COND_TIMEDWAIT(&card_poll_sleep_cond, &card_poll_sleep_cond_mutex, &ts); // sleep on card_poll_sleep_cond
		SAFE_MUTEX_UNLOCK(&card_poll_sleep_cond_mutex);
	}
	return NULL;
}

#ifdef WEBIF
static pid_t pid;

static void fwd_sig(int32_t sig)
{
	kill(pid, sig);
}

static void restart_daemon(void)
{
	while(1)
	{
		// start client process:
		pid = fork();
		if(!pid)
			{ return; } // client process=oscam process
		if(pid < 0)
			{ exit(1); }

		// set signal handler for the restart daemon:
		set_signal_handler(SIGINT, 3, fwd_sig);
#if defined(__APPLE__)
		set_signal_handler(SIGEMT, 3, fwd_sig);
#endif
		set_signal_handler(SIGTERM, 3, fwd_sig);
		set_signal_handler(SIGQUIT, 0, fwd_sig);
		set_signal_handler(SIGHUP , 0, fwd_sig);
		set_signal_handler(SIGUSR1, 0, fwd_sig);
		set_signal_handler(SIGUSR2, 0, fwd_sig);
		set_signal_handler(SIGALRM , 0, fwd_sig);
		set_signal_handler(SIGWINCH, 1, SIG_IGN);
		set_signal_handler(SIGPIPE , 0, SIG_IGN);
		set_signal_handler(OSCAM_SIGNAL_WAKEUP, 0, SIG_IGN);

		// restart control process:
		int32_t res = 0;
		int32_t status = 0;
		do
		{
			res = waitpid(pid, &status, 0);
			if(res == -1)
			{
				if(errno != EINTR)
					{ exit(1); }
			}
		}
		while(res != pid);

		if(cs_restart_mode == 2 && WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)
			{ status = 99; } // restart on segfault!
		else
			{ status = WEXITSTATUS(status); }

		// status=99 restart oscam, all other->terminate
		if(status != 99)
		{
			exit(status);
		}
	}
}

void cs_restart_oscam(void)
{
	exit_oscam = 99;
	cs_log("restart oscam requested");
}

int32_t cs_get_restartmode(void)
{
	return cs_restart_mode;
}
#endif

void cs_exit_oscam(void)
{
	exit_oscam = 1;
	cs_log("exit oscam requested");
}

static void pidfile_create(char *pidfile)
{
	FILE *f = fopen(pidfile, "w");
	if(f)
	{
		pid_t my_pid = getpid();
		cs_log("creating pidfile %s with pid %d", pidfile, my_pid);
		fprintf(f, "%d\n", my_pid);
		fclose(f);
	}
}

static bool running_under_valgrind;

static void detect_valgrind(void)
{
#ifdef __linux__
	char fname[32];
	snprintf(fname, sizeof(fname), "/proc/%d/maps", getpid());
	FILE *f = fopen(fname, "r");
	if (f) {
		char line[256];
		while (fgets(line, sizeof(line), f)) {
			if (strstr(line, "/valgrind/")) {
				running_under_valgrind = true;
				break;
			}
		}
	}
	fclose(f);
#endif
}

#ifdef BUILD_TESTS
extern void run_all_tests(void);
__attribute__ ((noreturn)) static void run_tests(void)
{
	run_all_tests();
	exit(0);
}
#else
static void run_tests(void) { }
#endif

const struct s_cardsystem *cardsystems[] =
{
#ifdef READER_NAGRA
	&reader_nagra,
#endif
#ifdef READER_NAGRA_MERLIN
	&reader_nagracak7,
#endif
#ifdef READER_IRDETO
	&reader_irdeto,
#endif
#ifdef READER_CONAX
	&reader_conax,
#endif
#ifdef READER_CRYPTOWORKS
	&reader_cryptoworks,
#endif
#ifdef READER_SECA
	&reader_seca,
#endif
#ifdef READER_VIACCESS
	&reader_viaccess,
#endif
#ifdef READER_VIDEOGUARD
	&reader_videoguard1,
	&reader_videoguard2,
	&reader_videoguard12,
#endif
#ifdef READER_DRE
	&reader_dre,
#endif
#ifdef READER_DRECAS
	&reader_drecas,
#endif
#ifdef READER_TONGFANG
	&reader_tongfang,
#endif
#ifdef READER_BULCRYPT
	&reader_bulcrypt,
#endif
#ifdef READER_GRIFFIN
	&reader_griffin,
#endif
#ifdef READER_DGCRYPT
	&reader_dgcrypt,
#endif
	NULL
};

const struct s_cardreader *cardreaders[] =
{
#ifdef CARDREADER_DB2COM
	&cardreader_db2com,
#endif
#if defined(CARDREADER_INTERNAL_AZBOX)
	&cardreader_internal_azbox,
#elif defined(CARDREADER_INTERNAL_COOLAPI)
	&cardreader_internal_cool,
#elif defined(CARDREADER_INTERNAL_COOLAPI2)
	&cardreader_internal_cool,
#elif defined(CARDREADER_INTERNAL_SCI)
	&cardreader_internal_sci,
#endif
#ifdef CARDREADER_PHOENIX
	&cardreader_mouse,
#endif
#ifdef CARDREADER_DRECAS
	&cardreader_drecas,
#endif
#ifdef CARDREADER_MP35
	&cardreader_mp35,
#endif
#ifdef CARDREADER_PCSC
	&cardreader_pcsc,
#endif
#ifdef CARDREADER_SC8IN1
	&cardreader_sc8in1,
#endif
#ifdef CARDREADER_SMARGO
	&cardreader_smargo,
#endif
#ifdef CARDREADER_SMART
	&cardreader_smartreader,
#endif
#if defined(CARDREADER_STAPI) || defined(CARDREADER_STAPI5)
	&cardreader_stapi,
#endif
#ifdef CARDREADER_STINGER
	&cardreader_stinger,
#endif
#ifdef WITH_EMU
	&cardreader_emu,
#endif

	NULL
};

static void find_conf_dir(void)
{
	static const char* confdirs[] =
		{
			"/etc/tuxbox/config/",
			"/etc/tuxbox/config/oscam/",
			"/var/tuxbox/config/",
			"/usr/keys/",
			"/var/keys/",
			"/var/etc/oscam/",
			"/var/etc/",
			"/var/oscam/",
			"/config/oscam/",
			NULL
		};

	char conf_file[128+16];
	int32_t i;

	if(cs_confdir[cs_strlen(cs_confdir) - 1] != '/')
		{ cs_strncat(cs_confdir, "/", sizeof(cs_confdir)); }

	if(snprintf(conf_file, sizeof(conf_file), "%soscam.conf", cs_confdir) < 0)
		{ return; }

	if(!access(conf_file, F_OK))
		{ return; }

	for(i=0; confdirs[i] != NULL; i++)
	{
		if(snprintf(conf_file, sizeof(conf_file), "%soscam.conf", confdirs[i]) < 0)
			{ return; }

		if (!access(conf_file, F_OK))
		{
			cs_strncpy(cs_confdir, confdirs[i], sizeof(cs_confdir));
			return;
		}
	}
}

int32_t main(int32_t argc, char *argv[])
{
	fix_stacksize();

	run_tests();
	int32_t i, j;
	prog_name = argv[0];
	struct timespec start_ts;
	cs_gettime(&start_ts); // Initialize clock_type

	if(pthread_key_create(&getclient, NULL))
	{
		fprintf(stderr, "Could not create getclient, exiting...");
		exit(1);
	}

	void (*mod_def[])(struct s_module *) =
	{
#ifdef MODULE_MONITOR
		module_monitor,
#endif
#ifdef MODULE_CAMD33
		module_camd33,
#endif
#ifdef MODULE_CAMD35
		module_camd35,
#endif
#ifdef MODULE_CAMD35_TCP
		module_camd35_tcp,
#endif
#ifdef MODULE_NEWCAMD
		module_newcamd,
#endif
#ifdef MODULE_CCCAM
		module_cccam,
#endif
#ifdef MODULE_PANDORA
		module_pandora,
#endif
#ifdef MODULE_GHTTP
		module_ghttp,
#endif
#ifdef CS_CACHEEX
		module_csp,
#endif
#ifdef MODULE_GBOX
		module_gbox,
#endif
#ifdef MODULE_CONSTCW
		module_constcw,
#endif
#ifdef MODULE_RADEGAST
		module_radegast,
#endif
#ifdef MODULE_SCAM
		module_scam,
#endif
#ifdef MODULE_SERIAL
		module_serial,
#endif
#ifdef HAVE_DVBAPI
		module_dvbapi,
#endif
		0
	};

	set_default_dirs_first();

	find_conf_dir();

	parse_cmdline_params(argc, argv);

	if(bg && do_daemon(1, 0))
	{
		printf("Error starting in background (errno=%d: %s)", errno, strerror(errno));
		cs_exit(1);
	}

	get_random_bytes_init();

#ifdef WEBIF
	if(cs_restart_mode)
		{ restart_daemon(); }
#endif

	memset(&cfg, 0, sizeof(struct s_config));
	cfg.max_pending = max_pending;

	if(cs_confdir[cs_strlen(cs_confdir) - 1] != '/') { cs_strncat(cs_confdir, "/", sizeof(cs_confdir)); }
	init_signal_pre(); // because log could cause SIGPIPE errors, init a signal handler first
	init_first_client();
	cs_lock_create(__func__, &system_lock, "system_lock", 5000);
	cs_lock_create(__func__, &config_lock, "config_lock", 10000);
	cs_lock_create(__func__, &gethostbyname_lock, "gethostbyname_lock", 10000);
	cs_lock_create(__func__, &clientlist_lock, "clientlist_lock", 5000);
	cs_lock_create(__func__, &readerlist_lock, "readerlist_lock", 5000);
	cs_lock_create(__func__, &fakeuser_lock, "fakeuser_lock", 5000);
	cs_lock_create(__func__, &ecmcache_lock, "ecmcache_lock", 5000);
	cs_lock_create(__func__, &ecm_pushed_deleted_lock, "ecm_pushed_deleted_lock", 5000);
	cs_lock_create(__func__, &readdir_lock, "readdir_lock", 5000);
	cs_lock_create(__func__, &cwcycle_lock, "cwcycle_lock", 5000);
	init_cache();
	cacheex_init_hitcache();
	init_config();
#ifdef CS_CACHEEX_AIO
	init_cw_cache();
	init_ecm_cache();
#endif
	cs_init_log();
	init_machine_info();
	init_check();
	if(!oscam_pidfile && cfg.pidfile)
		{ oscam_pidfile = cfg.pidfile; }
	if(!oscam_pidfile)
	{
		oscam_pidfile = get_tmp_dir_filename(default_pidfile, sizeof(default_pidfile), "oscam.pid");
	}
	if(oscam_pidfile)
		{ pidfile_create(oscam_pidfile); }
	cs_init_statistics();
	coolapi_open_all();
	init_stat();
	ssl_init();

	// These initializations *MUST* be called after init_config()
	// because modules depend on config values.
	for(i = 0; mod_def[i]; i++)
	{
		struct s_module *module = &modules[i];
		mod_def[i](module);
	}

	init_sidtab();
	init_readerdb();
#ifdef WITH_EMU
	add_emu_reader();
#endif
	cfg.account = init_userdb();
	init_signal();
	init_provid();
	init_srvid();
	init_tierid();
	init_fakecws();

	start_garbage_collector(gbdb);

	cacheex_init();

	init_len4caid();
	init_irdeto_guess_tab();

	write_versionfile(false);

	led_init();
	led_status_default();

	azbox_init();

	mca_init();

	global_whitelist_read();
	ratelimit_read();

#ifdef MODULE_SERIAL
	twin_read();
#endif

	for(i = 0; i < CS_MAX_MOD; i++)
	{
		struct s_module *module = &modules[i];
		if((module->type & MOD_CONN_NET))
		{
			for(j = 0; j < module->ptab.nports; j++)
			{
				start_listener(module, &module->ptab.ports[j]);
			}
		}
	}

	// set time for server to now to avoid 0 in monitor/webif
	first_client->last = time((time_t *)0);

	webif_init();

	start_thread("reader check", (void *) &reader_check, NULL, NULL, 1, 1);
	cw_process_thread_start();
	checkcache_process_thread_start();

	lcd_thread_start();

	do_report_emm_support();

	init_cardreader();

	cs_waitforcardinit();

	emm_load_cache();
	load_emmstat_from_file();

	led_status_starting();

	ac_init();

	gbox_send_init_hello();

	start_thread("card poll", (void *) &card_poll, NULL, NULL, 1, 1);

	for(i = 0; i < CS_MAX_MOD; i++)
	{
		struct s_module *module = &modules[i];
		if((module->type & MOD_CONN_SERIAL) && module->s_handler)
			{ module->s_handler(NULL, NULL, i); }
	}

	// main loop function
	process_clients();

	SAFE_COND_SIGNAL(&card_poll_sleep_cond); // Stop card_poll thread
	cw_process_thread_wakeup(); // Stop cw_process thread
	SAFE_COND_SIGNAL(&reader_check_sleep_cond); // Stop reader_check thread

	// Cleanup
#ifdef MODULE_GBOX
	stop_gbx_ticker();
#endif
#ifdef WITH_EMU
	stop_stream_server();
#endif
	webif_close();
	azbox_close();
	coolapi_close_all();
	mca_close();

	led_status_stopping();
	led_stop();
	lcd_thread_stop();

	remove_versionfile();

	stat_finish();
	dvbapi_stop_all_descrambling(0);
	dvbapi_save_channel_cache();
	emm_save_cache();
	save_emmstat_to_file();

	cccam_done_share();
	gbox_send_good_night();

	kill_all_clients();
	kill_all_readers();
	for(i = 0; i < CS_MAX_MOD; i++)
	{
		struct s_module *module = &modules[i];
		if((module->type & MOD_CONN_NET))
		{
			for(j = 0; j < module->ptab.nports; j++)
			{
				struct s_port *port = &module->ptab.ports[j];
				if(port->fd)
				{
					shutdown(port->fd, SHUT_RDWR);
					close(port->fd);
					port->fd = 0;
				}
			}
		}
	}

	if(oscam_pidfile)
		{ unlink(oscam_pidfile); }

	// sleep a bit, so hopefully all threads are stopped when we continue
	cs_sleepms(200);

	free_cache();
#ifdef CS_CACHEEX_AIO
	free_ecm_cache();
#endif
	cacheex_free_hitcache();
	webif_tpls_free();
	init_free_userdb(cfg.account);
	cfg.account = NULL;
	init_free_sidtab();
	free_readerdb();
	free_irdeto_guess_tab();
	config_free();
	ssl_done();

	detect_valgrind();
	if (!running_under_valgrind)
		cs_log("cardserver down");
	else
		cs_log("running under valgrind, waiting 5 seconds before stopping cardserver");
	log_free();

	if (running_under_valgrind) sleep(5); // HACK: Wait a bit for things to settle

	stop_garbage_collector();

	NULLFREE(first_client->account);
	NULLFREE(first_client);
	free(stb_boxtype);
	free(stb_boxname);

	// This prevents the compiler from removing config_mak from the final binary
	syslog_ident = config_mak;

	return exit_oscam;
}
