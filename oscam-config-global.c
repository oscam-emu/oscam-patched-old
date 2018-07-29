#define MODULE_LOG_PREFIX "config"

#include "globals.h"
#include "module-dvbapi.h"
#include "module-gbox.h"
#include "oscam-array.h"
#include "oscam-conf.h"
#include "oscam-conf-chk.h"
#include "oscam-conf-mk.h"
#include "oscam-config.h"
#include "oscam-net.h"
#include "oscam-string.h"

#define cs_conf "oscam.conf"

#define DEFAULT_HTTP_PORT   8888
#define DEFAULT_HTTP_ALLOW  "127.0.0.1,192.168.0.0-192.168.255.255,10.0.0.0-10.255.255.255,::1"

static void disablelog_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		cs_disable_log(strToIntVal(value, 0));
		return;
	}
	if(cfg.disablelog || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%d\n", cfg.disablelog); }
}

#if defined(WEBIF) || defined(MODULE_MONITOR)
static void loghistorylines_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		uint32_t newsize = strToUIntVal(value, 256);
		if(newsize < 64 && newsize != 0)
		{
			fprintf(stderr, "WARNING: loghistorylines is too small, adjusted to 64\n");
			newsize = 64;
		}
		cs_reinit_loghist(newsize);
		return;
	}
	if(cfg.loghistorylines != 256 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%u\n", cfg.loghistorylines); }
}
#endif

static void serverip_fn(const char *token, char *value, void *setting, FILE *f)
{
	IN_ADDR_T srvip = *(IN_ADDR_T *)setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			set_null_ip((IN_ADDR_T *)setting);
		}
		else
		{
			cs_inet_addr(value, (IN_ADDR_T *)setting);
		}
		return;
	}
	if(IP_ISSET(srvip) || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", cs_inet_ntoa(srvip)); }
}

void iprange_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_ip **ip = setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			clear_sip(ip);
		}
		else
		{
			chk_iprange(value, ip);
		}
		return;
	}
	value = mk_t_iprange(*ip);
	if(strlen(value) > 0 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", value); }
	free_mk_t(value);
}

void iprange_free_fn(void *setting)
{
	clear_sip(setting);
}

static void logfile_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		char *saveptr1 = NULL;
		cfg.logtostdout = 0;
		cfg.logtosyslog = 0;
		NULLFREE(cfg.logfile);
		if(strlen(value) > 0)
		{
			char *pch;
			for(pch = strtok_r(value, ";", &saveptr1); pch != NULL; pch = strtok_r(NULL, ";", &saveptr1))
			{
				pch = trim(pch);
				if(!strcmp(pch, "stdout")) { cfg.logtostdout = 1; }
				else if(!strcmp(pch, "syslog")) { cfg.logtosyslog = 1; }
				else
				{
					NULLFREE(cfg.logfile);
					if(!(cfg.logfile = cs_strdup(pch)))
						{ continue; }
				}
			}
		}
		else
		{
			if(!(cfg.logfile = cs_strdup(CS_LOGFILE)))
				{ cfg.logtostdout = 1; }
		}
		return;
	}
	if(cfg.logfile || cfg.logtostdout == 1 || cfg.logtosyslog == 1 || cfg.http_full_cfg)
	{
		value = mk_t_logfile();
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

void check_caidtab_fn(const char *token, char *value, void *setting, FILE *f)
{
	CAIDTAB *caid_table = setting;
	if(value)
	{
		if(strlen(value)) {
			chk_caidtab(value, caid_table);
		} else {
			caidtab_clear(caid_table);
		}
		return;
	}
	if(caid_table->ctnum || cfg.http_full_cfg)
	{
		value = mk_t_caidtab(caid_table);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

void chk_ftab_fn(const char *token, char *value, void *setting, FILE *f)
{
	FTAB *ftab = setting;
	if(value)
	{
		if(strlen(value))
			chk_ftab(value, ftab);
		else
			ftab_clear(ftab);
		return;
	}
	value = mk_t_ftab(ftab);
	if(strlen(value) > 0 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", value); }
	free_mk_t(value);
}


void caidvaluetab_fn(const char *token, char *value, void *setting, FILE *f)
{
	CAIDVALUETAB *caid_value_table = setting;
	if(value)
	{
		if (strlen(value)) {
			chk_caidvaluetab(value, caid_value_table);
			if (streq(token, "lb_retrylimits"))
			{
				int32_t i;
				for (i = 0; i < caid_value_table->cvnum; i++)
				{
					if (caid_value_table->cvdata[i].value < 50)
						caid_value_table->cvdata[i].value = 50;
				}
			}
		} else {
			caidvaluetab_clear(caid_value_table);
		}
		return;
	}
	if(caid_value_table->cvnum || cfg.http_full_cfg)
	{
		value = mk_t_caidvaluetab(caid_value_table);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

#ifdef CS_CACHEEX
void cacheex_valuetab_fn(const char *token, char *value, void *setting, FILE *f)
{
	CECSPVALUETAB *cacheex_value_table = setting;
	if(value)
	{
		if(strlen(value) == 0)
			{ clear_cacheextab(cacheex_value_table); }
		else
			{ chk_cacheex_valuetab(value, cacheex_value_table); }
		return;
	}
	if(cacheex_value_table->cevnum || cfg.http_full_cfg)
	{
		value = mk_t_cacheex_valuetab(cacheex_value_table);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

void cacheex_cwcheck_tab_fn(const char *token, char *value, void *setting, FILE *f)
{
	CWCHECKTAB *cacheex_value_table = setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			cacheex_value_table->cwchecknum = 0;
			NULLFREE(cacheex_value_table->cwcheckdata);
		}
		else
		{
			chk_cacheex_cwcheck_valuetab(value, cacheex_value_table);
		}
		return;
	}

	if(cacheex_value_table->cwchecknum || cfg.http_full_cfg)
	{
		value = mk_t_cacheex_cwcheck_valuetab(cacheex_value_table);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

void cacheex_hitvaluetab_fn(const char *token, char *value, void *setting, FILE *f)
{
	CECSPVALUETAB *cacheex_value_table = setting;
	if(value)
	{
		if(strlen(value) == 0)
			{ clear_cacheextab(cacheex_value_table); }
		else
			{ chk_cacheex_hitvaluetab(value, cacheex_value_table); }
		return;
	}
	if(cacheex_value_table->cevnum || cfg.http_full_cfg)
	{
		value = mk_t_cacheex_hitvaluetab(cacheex_value_table);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}
#endif

#ifdef __CYGWIN__
#include <windows.h>
#else
#include <sys/resource.h> // for setpriority
#endif

void global_fixups_fn(void *UNUSED(var))
{
	if(!cfg.usrfile) { cfg.disableuserfile = 1; }
	if(!cfg.mailfile) { cfg.disablemail = 1; }
	if(cfg.ctimeout < 10) { cfg.ctimeout = cfg.ctimeout * 1000; } // save always in ms

	if(cfg.nice < -20 || cfg.nice > 20) { cfg.nice = 99; }
	if(cfg.nice != 99)
	{
#ifndef __CYGWIN__
		setpriority(PRIO_PROCESS, 0, cfg.nice);
#else
		HANDLE WinId;
		uint32_t wprio;
		switch((cfg.nice + 20) / 10)
		{
		case  0:
			wprio = REALTIME_PRIORITY_CLASS;
			break;
		case  1:
			wprio = HIGH_PRIORITY_CLASS;
			break;
		case  2:
			wprio = NORMAL_PRIORITY_CLASS;
			break;
		default:
			wprio = IDLE_PRIORITY_CLASS;
			break;
		}
		WinId = GetCurrentProcess();
		SetPriorityClass(WinId, wprio);
#endif
	}
	if(cfg.netprio <= 0 || cfg.netprio > 20) { cfg.netprio = 0; }
	if(cfg.max_log_size != 0 && cfg.max_log_size <= 10) { cfg.max_log_size = 10; }
#ifdef WITH_LB
	if(cfg.lb_save > 0 && cfg.lb_save < 100) { cfg.lb_save = 100; }
	if(cfg.lb_nbest_readers < 2) { cfg.lb_nbest_readers = DEFAULT_NBEST; }
#endif
}

#define OFS(X) offsetof(struct s_config, X)
#define SIZEOF(X) sizeof(((struct s_config *)0)->X)

static const struct config_list global_opts[] =
{
	DEF_OPT_FIXUP_FUNC(global_fixups_fn),
#ifdef LEDSUPPORT
	DEF_OPT_INT8("enableled"                , OFS(enableled),           0),
#endif
	DEF_OPT_FUNC("disablelog"               , OFS(disablelog),          disablelog_fn),
#if defined(WEBIF) || defined(MODULE_MONITOR)
	DEF_OPT_FUNC("loghistorylines"          , OFS(loghistorylines),    loghistorylines_fn),
#endif
	DEF_OPT_FUNC("serverip"                 , OFS(srvip),               serverip_fn),
	DEF_OPT_FUNC("logfile"                  , OFS(logfile),             logfile_fn),
	DEF_OPT_INT32("initial_debuglevel"      , OFS(initial_debuglevel),  0), 
	DEF_OPT_STR("sysloghost"                , OFS(sysloghost),          NULL),
	DEF_OPT_INT32("syslogport"              , OFS(syslogport),          514),
	DEF_OPT_INT8("logduplicatelines"        , OFS(logduplicatelines),   0),
	DEF_OPT_STR("pidfile"                   , OFS(pidfile),             NULL),
	DEF_OPT_INT8("disableuserfile"          , OFS(disableuserfile),     1),
	DEF_OPT_INT8("disablemail"              , OFS(disablemail),         1),
	DEF_OPT_INT8("usrfileflag"              , OFS(usrfileflag),         0),
	DEF_OPT_UINT32("clienttimeout"          , OFS(ctimeout),            CS_CLIENT_TIMEOUT),
	DEF_OPT_UINT32("fallbacktimeout"        , OFS(ftimeout),            CS_CLIENT_TIMEOUT / 2),
	DEF_OPT_FUNC("fallbacktimeout_percaid"  , OFS(ftimeouttab),         caidvaluetab_fn),
	DEF_OPT_UINT32("clientmaxidle"          , OFS(cmaxidle),            CS_CLIENT_MAXIDLE),
	DEF_OPT_INT32("bindwait"                , OFS(bindwait),            CS_BIND_TIMEOUT),
	DEF_OPT_UINT32("netprio"                , OFS(netprio),             0),
	DEF_OPT_INT32("sleep"                   , OFS(tosleep),             0),
	DEF_OPT_INT32("unlockparental"          , OFS(ulparent),            0),
	DEF_OPT_INT32("nice"                    , OFS(nice),                99),
	DEF_OPT_INT32("maxlogsize"              , OFS(max_log_size),        10),
	DEF_OPT_INT8("waitforcards"             , OFS(waitforcards),        1),
	DEF_OPT_INT32("waitforcards_extra_delay", OFS(waitforcards_extra_delay), 500),
	DEF_OPT_INT8("preferlocalcards"         , OFS(preferlocalcards),    0),
	DEF_OPT_INT32("readerrestartseconds"    , OFS(reader_restart_seconds), 5),
	DEF_OPT_INT8("dropdups"                 , OFS(dropdups),            0),
	DEF_OPT_INT8("reload_useraccounts"      , OFS(reload_useraccounts), 0),
	DEF_OPT_INT8("reload_readers"           , OFS(reload_readers),      0),
	DEF_OPT_INT8("reload_provid"            , OFS(reload_provid),       0),
	DEF_OPT_INT8("reload_services_ids"      , OFS(reload_services_ids), 0),
	DEF_OPT_INT8("reload_tier_ids"          , OFS(reload_tier_ids),     0),
	DEF_OPT_INT8("reload_fakecws"           , OFS(reload_fakecws),      0),
	DEF_OPT_INT8("reload_ac_stat"           , OFS(reload_ac_stat),      0),
	DEF_OPT_INT8("reload_log"               , OFS(reload_log),          0),
	DEF_OPT_INT8("block_same_ip"            , OFS(block_same_ip),       1),
	DEF_OPT_INT8("block_same_name"          , OFS(block_same_name),     1),
	DEF_OPT_STR("usrfile"                   , OFS(usrfile),             NULL),
	DEF_OPT_STR("mailfile"                  , OFS(mailfile),            NULL),
	DEF_OPT_STR("cwlogdir"                  , OFS(cwlogdir),            NULL),
	DEF_OPT_STR("emmlogdir"                 , OFS(emmlogdir),           NULL),
#ifdef WITH_LB
	DEF_OPT_INT32("lb_mode"                 , OFS(lb_mode),             DEFAULT_LB_MODE),
	DEF_OPT_INT32("lb_save"                 , OFS(lb_save),             0),
	DEF_OPT_INT32("lb_nbest_readers"        , OFS(lb_nbest_readers),    DEFAULT_NBEST),
	DEF_OPT_INT32("lb_nfb_readers"          , OFS(lb_nfb_readers),      DEFAULT_NFB),
	DEF_OPT_INT32("lb_min_ecmcount"         , OFS(lb_min_ecmcount),     DEFAULT_MIN_ECM_COUNT),
	DEF_OPT_INT32("lb_max_ecmcount"         , OFS(lb_max_ecmcount),     DEFAULT_MAX_ECM_COUNT),
	DEF_OPT_INT32("lb_reopen_seconds"       , OFS(lb_reopen_seconds),   DEFAULT_REOPEN_SECONDS),
	DEF_OPT_INT8("lb_reopen_invalid"        , OFS(lb_reopen_invalid),   1),
	DEF_OPT_INT8("lb_force_reopen_always"   , OFS(lb_force_reopen_always),   0),
	DEF_OPT_INT32("lb_retrylimit"           , OFS(lb_retrylimit),       DEFAULT_RETRYLIMIT),
	DEF_OPT_INT32("lb_stat_cleanup"         , OFS(lb_stat_cleanup),     DEFAULT_LB_STAT_CLEANUP),
	DEF_OPT_INT32("lb_max_readers"          , OFS(lb_max_readers),      0),
	DEF_OPT_INT32("lb_auto_betatunnel"      , OFS(lb_auto_betatunnel),  DEFAULT_LB_AUTO_BETATUNNEL),
	DEF_OPT_INT32("lb_auto_betatunnel_mode" , OFS(lb_auto_betatunnel_mode), DEFAULT_LB_AUTO_BETATUNNEL_MODE),
	DEF_OPT_INT32("lb_auto_betatunnel_prefer_beta"  , OFS(lb_auto_betatunnel_prefer_beta), DEFAULT_LB_AUTO_BETATUNNEL_PREFER_BETA),
	DEF_OPT_STR("lb_savepath"               , OFS(lb_savepath),         NULL),
	DEF_OPT_FUNC("lb_retrylimits"           , OFS(lb_retrylimittab), caidvaluetab_fn),
	DEF_OPT_FUNC("lb_nbest_percaid"         , OFS(lb_nbest_readers_tab), caidvaluetab_fn),
	DEF_OPT_FUNC("lb_noproviderforcaid"     , OFS(lb_noproviderforcaid), check_caidtab_fn),
	DEF_OPT_INT32("lb_auto_timeout"         , OFS(lb_auto_timeout), DEFAULT_LB_AUTO_TIMEOUT),
	DEF_OPT_INT32("lb_auto_timeout_p"       , OFS(lb_auto_timeout_p), DEFAULT_LB_AUTO_TIMEOUT_P),
	DEF_OPT_INT32("lb_auto_timeout_t"       , OFS(lb_auto_timeout_t), DEFAULT_LB_AUTO_TIMEOUT_T),
#endif
	DEF_OPT_FUNC("double_check_caid"        , OFS(double_check_caid),   check_caidtab_fn),
	DEF_OPT_STR("ecmfmt"                    , OFS(ecmfmt),              NULL),
	DEF_OPT_INT32("resolvegethostbyname"    , OFS(resolve_gethostbyname), 0),
	DEF_OPT_INT32("failbantime"             , OFS(failbantime),         0),
	DEF_OPT_INT32("failbancount"            , OFS(failbancount),        0),
	DEF_OPT_INT8("suppresscmd08"            , OFS(c35_suppresscmd08),   0),
	DEF_OPT_INT8("getblockemmauprovid"      , OFS(getblockemmauprovid), 0),
	DEF_OPT_INT8("double_check"             , OFS(double_check),        0),
	DEF_OPT_INT8("disablecrccws"                 , OFS(disablecrccws),            0),
	DEF_OPT_FUNC("disablecrccws_only_for"	, OFS(disablecrccws_only_for),     chk_ftab_fn),
	DEF_LAST_OPT
};

#ifdef CS_ANTICASC
static void anticasc_fixups_fn(void *UNUSED(var))
{
	if(cfg.ac_users < 0) { cfg.ac_users = 0; }
	if(cfg.ac_stime < 0) { cfg.ac_stime = 2; }
	if(cfg.ac_samples < 2 || cfg.ac_samples > 10) { cfg.ac_samples = 10; }
	if(cfg.ac_penalty < 0 || cfg.ac_penalty > 3) { cfg.ac_penalty = 0; }
	if(cfg.ac_fakedelay < 100 || cfg.ac_fakedelay > 3000) { cfg.ac_fakedelay = 1000; }
	if(cfg.ac_denysamples < 2 || cfg.ac_denysamples > cfg.ac_samples - 1) { cfg.ac_denysamples = cfg.ac_samples - 1; }
	if(cfg.ac_denysamples + 1 > cfg.ac_samples) { cfg.ac_denysamples = cfg.ac_samples - 1; }
	if(cfg.acosc_max_active_sids < 0) { cfg.acosc_max_active_sids = 0; }
	if(cfg.acosc_zap_limit < 0) { cfg.acosc_zap_limit = 0; }
	if(cfg.acosc_penalty < 0 || cfg.acosc_penalty > 3) { cfg.acosc_penalty = 0; }
	if(cfg.acosc_penalty_duration < 0) { cfg.acosc_penalty_duration = 0; }
	if(cfg.acosc_delay < 0 || cfg.acosc_delay > 4000) { cfg.acosc_delay = 0; }
}

static bool anticasc_should_save_fn(void *UNUSED(var))
{
	return cfg.ac_enabled || cfg.acosc_enabled;
}

static const struct config_list anticasc_opts[] =
{
	DEF_OPT_SAVE_FUNC(anticasc_should_save_fn),
	DEF_OPT_FIXUP_FUNC(anticasc_fixups_fn),
	DEF_OPT_INT8("enabled"			, OFS(ac_enabled),		0),
	DEF_OPT_INT32("numusers"		, OFS(ac_users),		0),
	DEF_OPT_INT32("sampletime"		, OFS(ac_stime),		2),
	DEF_OPT_INT32("samples"			, OFS(ac_samples),		10),
	DEF_OPT_INT8("penalty"			, OFS(ac_penalty),		0),
	DEF_OPT_STR("aclogfile"			, OFS(ac_logfile),		NULL),
	DEF_OPT_INT32("fakedelay"		, OFS(ac_fakedelay),		3000),
	DEF_OPT_INT32("denysamples"		, OFS(ac_denysamples),		8),
	DEF_OPT_INT8("acosc_enabled"		, OFS(acosc_enabled),		0 ),
	DEF_OPT_INT8("acosc_max_active_sids"	, OFS(acosc_max_active_sids),	0 ),
	DEF_OPT_INT8("acosc_zap_limit"		, OFS(acosc_zap_limit),		0 ),
	DEF_OPT_INT8("acosc_penalty"		, OFS(acosc_penalty),		0 ),
	DEF_OPT_INT32("acosc_penalty_duration"	, OFS(acosc_penalty_duration),	0 ),
	DEF_OPT_INT32("acosc_delay"		, OFS(acosc_delay),		0 ),
	DEF_LAST_OPT
};
#else
static const struct config_list anticasc_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_MONITOR
static bool monitor_should_save_fn(void *UNUSED(var))
{
	return cfg.mon_port;
}

static const struct config_list monitor_opts[] =
{
	DEF_OPT_SAVE_FUNC(monitor_should_save_fn),
	DEF_OPT_INT32("port"		, OFS(mon_port),	0),
	DEF_OPT_FUNC("serverip"		, OFS(mon_srvip),	serverip_fn),
	DEF_OPT_FUNC("nocrypt"		, OFS(mon_allowed),	iprange_fn, .free_value = iprange_free_fn),
	DEF_OPT_INT32("aulow"		, OFS(aulow),		30),
	DEF_OPT_UINT8("monlevel"	, OFS(mon_level),	2),
	DEF_OPT_INT32("hideclient_to"	, OFS(hideclient_to),	25),
	DEF_LAST_OPT
};
#else
static const struct config_list monitor_opts[] = { DEF_LAST_OPT };
#endif

#ifdef WEBIF
static void http_port_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		cfg.http_port = 0;
		if(value[0])
		{
			if(value[0] == '+')
			{
				if(config_enabled(WITH_SSL))
				{
					cfg.http_use_ssl = 1;
				}
				else
				{
					fprintf(stderr, "Warning: OSCam compiled without SSL support.\n");
				}
				cfg.http_port = strtoul(value + 1, NULL, 10);
			}
			else
			{
				cfg.http_port = strtoul(value, NULL, 10);
			}
		}
		return;
	}
	fprintf_conf(f, token, "%s%d\n", cfg.http_use_ssl ? "+" : "", cfg.http_port);
}

static void http_dyndns_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	int i;
	if(value)
	{
		char *ptr, *saveptr1 = NULL;
		memset(cfg.http_dyndns, 0, sizeof(cfg.http_dyndns));
		for(i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < MAX_HTTP_DYNDNS) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
		{
			trim(ptr);
			cs_strncpy((char *)cfg.http_dyndns[i], ptr, sizeof(cfg.http_dyndns[i]));
		}
		return;
	}
	if(strlen((const char *)(cfg.http_dyndns[0])) > 0 || cfg.http_full_cfg)
	{
		fprintf_conf(f, token, "%s", ""); // it should not have \n at the end
		for(i = 0; i < MAX_HTTP_DYNDNS; i++)
		{
			if(cfg.http_dyndns[i][0])
			{
				fprintf(f, "%s%s", i > 0 ? "," : "", cfg.http_dyndns[i]);
			}
		}
		fprintf(f, "\n");
	}
}

static bool webif_should_save_fn(void *UNUSED(var))
{
	return cfg.http_port;
}

static const struct config_list webif_opts[] =
{
	DEF_OPT_SAVE_FUNC(webif_should_save_fn),
	DEF_OPT_FUNC("httpport"			 , OFS(http_port)			, http_port_fn),
	DEF_OPT_FUNC("serverip"			 , OFS(http_srvip)			, serverip_fn),
	DEF_OPT_STR("httpuser"			 , OFS(http_user)			, NULL),
	DEF_OPT_STR("httppwd"			 , OFS(http_pwd)			, NULL),
	DEF_OPT_STR("httpcss"			 , OFS(http_css)			, NULL),
	DEF_OPT_STR("httpjscript"		 , OFS(http_jscript)			, NULL),
	DEF_OPT_STR("httpscript"		 , OFS(http_script)			, NULL),
	DEF_OPT_STR("httptpl"			 , OFS(http_tpl)			, NULL),
	DEF_OPT_STR("httppiconpath"		 , OFS(http_piconpath)			, NULL),
	DEF_OPT_STR("httphelplang"		 , OFS(http_help_lang)			, "en"),
	DEF_OPT_STR("httplocale"		 , OFS(http_locale)			, NULL),
	DEF_OPT_INT8("http_prepend_embedded_css" , OFS(http_prepend_embedded_css)	, 0),
	DEF_OPT_INT32("httprefresh"		 , OFS(http_refresh)			, 0),
	DEF_OPT_INT32("httppollrefresh"		 , OFS(poll_refresh)			, 60),
	DEF_OPT_INT8("httphideidleclients"	 , OFS(http_hide_idle_clients)		, 1),
	DEF_OPT_STR("httphidetype"		 , OFS(http_hide_type)			, NULL),
	DEF_OPT_INT8("httpshowpicons"		 , OFS(http_showpicons)			, 0),
	DEF_OPT_INT8("httppiconsize"		 , OFS(http_picon_size)			, 0),
	DEF_OPT_INT8("httpshowmeminfo"		 , OFS(http_showmeminfo)		, 0),
	DEF_OPT_INT8("httpshowuserinfo"		 , OFS(http_showuserinfo)		, 0),
	DEF_OPT_INT8("httpshowreaderinfo"	 , OFS(http_showreaderinfo)		, 0),
	DEF_OPT_INT8("httpshowcacheexinfo"	 , OFS(http_showcacheexinfo)		, 0),
	DEF_OPT_INT8("httpshowecminfo"		 , OFS(http_showecminfo)		, 0),
	DEF_OPT_INT8("httpshowloadinfo"		 , OFS(http_showloadinfo)		, 0),
	DEF_OPT_FUNC("httpallowed"		 , OFS(http_allowed)			, iprange_fn, .free_value = iprange_free_fn),
	DEF_OPT_INT8("httpreadonly"		 , OFS(http_readonly)			, 0),
	DEF_OPT_INT8("httpsavefullcfg"		 , OFS(http_full_cfg)			, 0),
	DEF_OPT_INT8("httpoverwritebakfile"	 , OFS(http_overwrite_bak_file)		, 0),
	DEF_OPT_STR("httpcert"			 , OFS(http_cert)			, NULL),
	DEF_OPT_INT8("https_force_secure_mode"	 , OFS(https_force_secure_mode)		, 1),
	DEF_OPT_FUNC("httpdyndns"		 , OFS(http_dyndns)			, http_dyndns_fn),
	DEF_OPT_INT32("aulow"			 , OFS(aulow)				, 30),
	DEF_OPT_INT32("hideclient_to"		 , OFS(hideclient_to)			, 25),
	DEF_OPT_STR("httposcamlabel"		 , OFS(http_oscam_label)		, "OSCam"),
	DEF_OPT_INT32("httpemmuclean"		 , OFS(http_emmu_clean)			, 256),
	DEF_OPT_INT32("httpemmsclean"		 , OFS(http_emms_clean)			, -1),
	DEF_OPT_INT32("httpemmgclean"		 , OFS(http_emmg_clean)			, -1),
#ifdef WEBIF_LIVELOG
	DEF_OPT_INT8("http_status_log"		 , OFS(http_status_log)			, 0),
#else
	DEF_OPT_INT8("http_status_log"		 , OFS(http_status_log)			, 1),
#endif
#ifndef WEBIF_JQUERY
	DEF_OPT_STR("http_extern_jquery"	 , OFS(http_extern_jquery)		, "//code.jquery.com/jquery-1.12.4.min.js"),
#endif
	DEF_LAST_OPT
};
#else
static const struct config_list webif_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_CAMD33
static bool camd33_should_save_fn(void *UNUSED(var))
{
	return cfg.c33_port;
}

static const struct config_list camd33_opts[] =
{
	DEF_OPT_SAVE_FUNC(camd33_should_save_fn),
	DEF_OPT_INT32("port"	, OFS(c33_port),	0),
	DEF_OPT_FUNC("serverip"	, OFS(c33_srvip),	serverip_fn),
	DEF_OPT_FUNC("nocrypt"	, OFS(c33_plain),	iprange_fn, .free_value = iprange_free_fn),
	DEF_OPT_INT32("passive"	, OFS(c33_passive),	0),
	DEF_OPT_HEX("key"	, OFS(c33_key),		SIZEOF(c33_key)),
	DEF_LAST_OPT
};
#else
static const struct config_list camd33_opts[] = { DEF_LAST_OPT };
#endif


void cache_fixups_fn(void *UNUSED(var))
{
	if(cfg.max_cache_time < ((int32_t)(cfg.ctimeout + 500) / 1000 + 3)) { cfg.max_cache_time = ((cfg.ctimeout + 500) / 1000 + 3); }
#ifdef CW_CYCLE_CHECK
	if(cfg.maxcyclelist > 4000) { cfg.maxcyclelist = 4000; }
	if(cfg.keepcycletime > 240) { cfg.keepcycletime = 240; }
	if(cfg.cwcycle_sensitive > 4) { cfg.cwcycle_sensitive = 4; }
	if(cfg.cwcycle_sensitive == 1) { cfg.cwcycle_sensitive = 2; }
#endif
}

static bool cache_should_save_fn(void *UNUSED(var))
{
	return cfg.delay > 0 || cfg.max_cache_time != 15
#ifdef CS_CACHEEX
		   || cfg.cacheex_wait_timetab.cevnum || cfg.cacheex_enable_stats > 0 || cfg.csp_port || cfg.csp.filter_caidtab.cevnum || cfg.csp.allow_request == 0 || cfg.csp.allow_reforward > 0
#endif
#ifdef CW_CYCLE_CHECK
		   || cfg.cwcycle_check_enable || cfg.cwcycle_check_caidtab.ctnum || cfg.maxcyclelist != 500 || cfg.keepcycletime || cfg.onbadcycle || cfg.cwcycle_dropold || cfg.cwcycle_sensitive || cfg.cwcycle_allowbadfromffb || cfg.cwcycle_usecwcfromce
#endif
		   ;
}

static const struct config_list cache_opts[] =
{
	DEF_OPT_SAVE_FUNC(cache_should_save_fn),
	DEF_OPT_FIXUP_FUNC(cache_fixups_fn),
	DEF_OPT_UINT32("delay"			, OFS(delay),			CS_DELAY),
	DEF_OPT_INT32("max_time"		, OFS(max_cache_time),		DEFAULT_MAX_CACHE_TIME),
#ifdef CS_CACHEEX
	DEF_OPT_INT32("max_hit_time"		, OFS(max_hitcache_time),	DEFAULT_MAX_HITCACHE_TIME),
	DEF_OPT_FUNC("wait_time"		, OFS(cacheex_wait_timetab),	cacheex_valuetab_fn),
	DEF_OPT_FUNC("cacheex_mode1_delay"	, OFS(cacheex_mode1_delay_tab), caidvaluetab_fn),
	DEF_OPT_UINT8("cacheexenablestats"	, OFS(cacheex_enable_stats),	0),
	DEF_OPT_INT32("csp_port"		, OFS(csp_port),		0),
	DEF_OPT_FUNC("csp_serverip"		, OFS(csp_srvip),		serverip_fn),
	DEF_OPT_FUNC("csp_ecm_filter"		, OFS(csp.filter_caidtab),	cacheex_hitvaluetab_fn),
	DEF_OPT_UINT8("csp_allow_request"	, OFS(csp.allow_request),	1),
	DEF_OPT_UINT8("csp_allow_reforward"	, OFS(csp.allow_reforward),	0),
	DEF_OPT_FUNC("cacheex_cw_check"		, OFS(cacheex_cwcheck_tab),	cacheex_cwcheck_tab_fn),
	DEF_OPT_UINT8("wait_until_ctimeout"	, OFS(wait_until_ctimeout),	0),
	DEF_OPT_UINT8("csp_block_fakecws"	, OFS(csp.block_fakecws),	0),
#endif
#ifdef CW_CYCLE_CHECK
	DEF_OPT_INT8("cwcycle_check_enable"	, OFS(cwcycle_check_enable),	0),
	DEF_OPT_FUNC("cwcycle_check_caid"	, OFS(cwcycle_check_caidtab),	check_caidtab_fn),
	DEF_OPT_INT32("cwcycle_maxlist"		, OFS(maxcyclelist),		500),
	DEF_OPT_INT32("cwcycle_keeptime"	, OFS(keepcycletime),		15),
	DEF_OPT_INT8("cwcycle_onbad"		, OFS(onbadcycle),		1),
	DEF_OPT_INT8("cwcycle_dropold"		, OFS(cwcycle_dropold),		1),
	DEF_OPT_INT8("cwcycle_sensitive"	, OFS(cwcycle_sensitive),	4),
	DEF_OPT_INT8("cwcycle_allowbadfromffb"	, OFS(cwcycle_allowbadfromffb),	0),
	DEF_OPT_INT8("cwcycle_usecwcfromce"	, OFS(cwcycle_usecwcfromce),	0),
#endif
	DEF_LAST_OPT
};

#ifdef MODULE_CAMD35
static bool camd35_should_save_fn(void *UNUSED(var))
{
	return cfg.c35_port;
}

static const struct config_list camd35_opts[] =
{
	DEF_OPT_SAVE_FUNC(camd35_should_save_fn),
	DEF_OPT_INT32("port"		, OFS(c35_port),		0),
	DEF_OPT_FUNC("serverip"		, OFS(c35_srvip),		serverip_fn),
	DEF_OPT_INT8("suppresscmd08"	, OFS(c35_udp_suppresscmd08),	0),
	DEF_LAST_OPT
};
#else
static const struct config_list camd35_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_NEWCAMD
static void porttab_fn(const char *token, char *value, void *setting, FILE *f)
{
	PTAB *ptab = setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			clear_ptab(ptab);
		}
		else
		{
			chk_port_tab(value, ptab);
		}
		return;
	}
	value = mk_t_newcamd_port();
	fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}
#endif

#ifdef MODULE_CAMD35_TCP
static void porttab_camd35_fn(const char *token, char *value, void *setting, FILE *f)
{
	PTAB *ptab = setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			clear_ptab(ptab);
		}
		else
		{
			chk_port_camd35_tab(value, ptab);
		}
		return;
	}
	value = mk_t_camd35tcp_port();
	fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}
#endif

#if defined(MODULE_NEWCAMD) || defined(MODULE_CAMD35_TCP)
static void porttab_free_fn(void *setting)
{
	clear_ptab(setting);
}
#endif

#ifdef MODULE_CAMD35_TCP
static bool cs378x_should_save_fn(void *UNUSED(var))
{
	return cfg.c35_tcp_ptab.nports && cfg.c35_tcp_ptab.ports[0].s_port;
}

static const struct config_list cs378x_opts[] =
{
	DEF_OPT_SAVE_FUNC(cs378x_should_save_fn),
	DEF_OPT_FUNC("port"				, OFS(c35_tcp_ptab)			, porttab_camd35_fn	, .free_value = porttab_free_fn),
	DEF_OPT_FUNC("serverip"			, OFS(c35_tcp_srvip)		, serverip_fn),
	DEF_OPT_INT8("suppresscmd08"	, OFS(c35_tcp_suppresscmd08), 0),
	DEF_LAST_OPT
};
#else
static const struct config_list cs378x_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_NEWCAMD
static bool newcamd_should_save_fn(void *UNUSED(var))
{
	return cfg.ncd_ptab.nports && cfg.ncd_ptab.ports[0].s_port;
}

static const struct config_list newcamd_opts[] =
{
	DEF_OPT_SAVE_FUNC(newcamd_should_save_fn),
	DEF_OPT_FUNC("port"			, OFS(ncd_ptab)		, porttab_fn, .free_value = porttab_free_fn),
	DEF_OPT_FUNC("serverip"		, OFS(ncd_srvip)	, serverip_fn),
	DEF_OPT_FUNC("allowed"		, OFS(ncd_allowed)	, iprange_fn, .free_value = iprange_free_fn),
	DEF_OPT_HEX("key"			, OFS(ncd_key)		, SIZEOF(ncd_key)),
	DEF_OPT_INT8("keepalive"	, OFS(ncd_keepalive), DEFAULT_NCD_KEEPALIVE),
	DEF_OPT_INT8("mgclient"		, OFS(ncd_mgclient)	, 0),
	DEF_LAST_OPT
};
#else
static const struct config_list newcamd_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_CCCAM
static void cccam_port_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		int i;
		char *ptr, *saveptr1 = NULL;
		memset(cfg.cc_port, 0, sizeof(cfg.cc_port));
		for(i = 0, ptr = strtok_r(value, ",", &saveptr1); ptr && i < CS_MAXPORTS; ptr = strtok_r(NULL, ",", &saveptr1))
		{
			cfg.cc_port[i] = strtoul(ptr, NULL, 10);
			if(cfg.cc_port[i])
				{ i++; }
		}
		return;
	}
	value = mk_t_cccam_port();
	fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static bool cccam_should_save_fn(void *UNUSED(var))
{
	return cfg.cc_port[0];
}

static const struct config_list cccam_opts[] =
{
	DEF_OPT_SAVE_FUNC(cccam_should_save_fn),
	DEF_OPT_FUNC("port"			, OFS(cc_port),			cccam_port_fn),
	DEF_OPT_FUNC("serverip"			, OFS(cc_srvip),		serverip_fn),
	DEF_OPT_HEX("nodeid"			, OFS(cc_fixed_nodeid),		SIZEOF(cc_fixed_nodeid)),
	DEF_OPT_SSTR("version"			, OFS(cc_version),		"", SIZEOF(cc_version)),
	DEF_OPT_INT8("reshare"			, OFS(cc_reshare),		10),
	DEF_OPT_INT8("reshare_mode"		, OFS(cc_reshare_services),	4),
	DEF_OPT_INT8("ignorereshare"		, OFS(cc_ignore_reshare),	0),
	DEF_OPT_INT8("forward_origin_card"	, OFS(cc_forward_origin_card),	0),
	DEF_OPT_INT8("stealth"			, OFS(cc_stealth),		0),
	DEF_OPT_INT32("updateinterval"		, OFS(cc_update_interval),	DEFAULT_UPDATEINTERVAL),
	DEF_OPT_INT8("minimizecards"		, OFS(cc_minimize_cards),	0),
	DEF_OPT_INT8("keepconnected"		, OFS(cc_keep_connected),	1),
	DEF_OPT_UINT32("recv_timeout"		, OFS(cc_recv_timeout),		DEFAULT_CC_RECV_TIMEOUT),
	DEF_LAST_OPT
};
#else
static const struct config_list cccam_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_PANDORA
static bool pandora_should_save_fn(void *UNUSED(var))
{
	return cfg.pand_port;
}

static const struct config_list pandora_opts[] =
{
	DEF_OPT_SAVE_FUNC(pandora_should_save_fn),
	DEF_OPT_INT32("pand_port"		, OFS(pand_port),		0),
	DEF_OPT_FUNC("pand_srvid"		, OFS(pand_srvip),		serverip_fn),
	DEF_OPT_STR("pand_usr"			, OFS(pand_usr),		NULL),
	DEF_OPT_STR("pand_pass"			, OFS(pand_pass),		NULL),
	DEF_OPT_INT8("pand_ecm"			, OFS(pand_ecm),		0),
	DEF_OPT_INT8("pand_skip_send_dw"	, OFS(pand_skip_send_dw),	0),
	DEF_OPT_FUNC("pand_allowed"		, OFS(pand_allowed),		iprange_fn, .free_value = iprange_free_fn),
	DEF_LAST_OPT
};
#else
static const struct config_list pandora_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_SCAM
static bool scam_should_save_fn(void *UNUSED(var))
{
	return cfg.scam_port;
}
static const struct config_list scam_opts[] =
{
	DEF_OPT_SAVE_FUNC(scam_should_save_fn),
	DEF_OPT_INT32("port"    , OFS(scam_port),    0),
	DEF_OPT_FUNC("serverip" , OFS(scam_srvip),   serverip_fn),
	DEF_OPT_FUNC("allowed"  , OFS(scam_allowed), iprange_fn, .free_value = iprange_free_fn),
	DEF_LAST_OPT
};
#else
static const struct config_list scam_opts[] = { DEF_LAST_OPT };
#endif

#ifdef WITH_EMU
static bool streamrelay_should_save_fn(void *UNUSED(var))
{
	return 1;
}
static const struct config_list streamrelay_opts[] =
{
	DEF_OPT_SAVE_FUNC(streamrelay_should_save_fn),
	DEF_OPT_STR("stream_source_host"          , OFS(emu_stream_source_host),          "127.0.0.1"),
	DEF_OPT_INT32("stream_source_port"        , OFS(emu_stream_source_port),          8001),
	DEF_OPT_STR("stream_source_auth_user"     , OFS(emu_stream_source_auth_user),     NULL),
	DEF_OPT_STR("stream_source_auth_password" , OFS(emu_stream_source_auth_password), NULL),
	DEF_OPT_INT32("stream_relay_port"         , OFS(emu_stream_relay_port),           17999),
	DEF_OPT_UINT32("stream_ecm_delay"         , OFS(emu_stream_ecm_delay),            600),
	DEF_OPT_INT8("stream_relay_enabled"       , OFS(emu_stream_relay_enabled),        1),
	DEF_OPT_INT8("stream_emm_enabled"         , OFS(emu_stream_emm_enabled),          1),
	DEF_LAST_OPT
};
#else
static const struct config_list streamrelay_opts[] = { DEF_LAST_OPT };
#endif


#ifdef MODULE_RADEGAST
static bool radegast_should_save_fn(void *UNUSED(var))
{
	return cfg.rad_port;
}

static const struct config_list radegast_opts[] =
{
	DEF_OPT_SAVE_FUNC(radegast_should_save_fn),
	DEF_OPT_INT32("port"	, OFS(rad_port),	0),
	DEF_OPT_FUNC("serverip"	, OFS(rad_srvip),	serverip_fn),
	DEF_OPT_FUNC("allowed"	, OFS(rad_allowed),	iprange_fn, .free_value = iprange_free_fn),
	DEF_OPT_STR("user"	, OFS(rad_usr),		NULL),
	DEF_LAST_OPT
};
#else
static const struct config_list radegast_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_SERIAL
static bool serial_should_save_fn(void *UNUSED(var))
{
	return cfg.ser_device != NULL;
}

static const struct config_list serial_opts[] =
{
	DEF_OPT_SAVE_FUNC(serial_should_save_fn),
	DEF_OPT_STR("device"	, OFS(ser_device),	NULL),
	DEF_LAST_OPT
};
#else
static const struct config_list serial_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_GBOX

static void gbox_password_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if (value)
	{
	    const char *s;
		s=value;
    	if (s[strspn(s, "0123456789abcdefABCDEF")] == 0)
		{
    		/* valid Hexa symbol */
			cfg.gbox_password = a2i(value, 8);
			return;
	 	}
	 	else
	 	{
	 		cfg.gbox_password = 0;
	 	}
	 }
	if (cfg.gbox_password != 0)
	{
		fprintf_conf(f, token, "%08X\n", cfg.gbox_password);
	}
}

static void gbox_block_ecm_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if (value)
	{
		char *ptr1, *saveptr1 = NULL;
		const char *s;
		memset(cfg.gbox_block_ecm, 0, sizeof(cfg.gbox_block_ecm));
		int n = 0, i;
		for (i = 0, ptr1 = strtok_r(value, ",", &saveptr1); (i < 4) && (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1))
		{
			s=ptr1;
			if ((n < GBOX_MAX_BLOCKED_ECM) && (s[strspn(s, "0123456789abcdefABCDEF")] == 0))
			{ cfg.gbox_block_ecm[n++] = a2i(ptr1, 4); }
		}
		cfg.gbox_block_ecm_num = n;
		return;
	}
	if (cfg.gbox_block_ecm_num > 0)
	{
		value = mk_t_gbox_block_ecm();
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

static void accept_remm_peer_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if (value)
	{
		char *ptr1, *saveptr1 = NULL;
		const char *s;
		memset(cfg.accept_remm_peer, 0, sizeof(cfg.accept_remm_peer));
		int n = 0, i;
		for (i = 0, ptr1 = strtok_r(value, ",", &saveptr1); (i < 4) && (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1))
		{
			s=ptr1;
			if ((n < GBOX_MAX_REMM_PEERS) && (s[strspn(s, "0123456789abcdefABCDEF")] == 0))
			{ cfg.accept_remm_peer[n++] = a2i(ptr1, 4); }
		}
		cfg.accept_remm_peer_num = n;
		return;
	}
	if (cfg.accept_remm_peer_num > 0)
	{
		value = mk_t_accept_remm_peer();
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

static void gbox_ignored_peer_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if (value)
	{
		char *ptr1, *saveptr1 = NULL;
		const char *s;
		memset(cfg.gbox_ignored_peer, 0, sizeof(cfg.gbox_ignored_peer));
		int n = 0, i;
		for (i = 0, ptr1 = strtok_r(value, ",", &saveptr1); (i < 4) && (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1))
		{
			s=ptr1;
			if ((n < GBOX_MAX_IGNORED_PEERS) && (s[strspn(s, "0123456789abcdefABCDEF")] == 0))
			{ cfg.gbox_ignored_peer[n++] = a2i(ptr1, 4); }	
		}
		cfg.gbox_ignored_peer_num = n;
		return;
	}
	if (cfg.gbox_ignored_peer_num > 0)
	{
		value = mk_t_gbox_ignored_peer();
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

static void gbox_proxy_card_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if (value)
	{
		char *ptr1, *saveptr1 = NULL;
		const char *s;
		memset(cfg.gbox_proxy_card, 0, sizeof(cfg.gbox_proxy_card));
		int n = 0, i;
		for (i = 0, ptr1 = strtok_r(value, ",", &saveptr1); (i < 8) && (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1))
		{
			s=ptr1;
			if ((n < GBOX_MAX_PROXY_CARDS) && (s[strspn(s, "0123456789abcdefABCDEF")] == 0))
				{ cfg.gbox_proxy_card[n++] = a2i(ptr1, 8); }
		}
		cfg.gbox_proxy_cards_num = n;
		return;
	 }

	if (cfg.gbox_proxy_cards_num > 0)
	{
		value = mk_t_gbox_proxy_card();
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

static void gbox_port_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		int i;
		char *ptr, *saveptr1 = NULL;
		memset(cfg.gbox_port, 0, sizeof(cfg.gbox_port));
		for(i = 0, ptr = strtok_r(value, ",", &saveptr1); ptr && i < CS_MAXPORTS; ptr = strtok_r(NULL, ",", &saveptr1))
		{
			cfg.gbox_port[i] = strtoul(ptr, NULL, 10);
			if(cfg.gbox_port[i])
				{ i++; }
		}
		return;
	}
	value = mk_t_gbox_port();
	fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void gbox_my_vers_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		const char *s;
		s=value;
		int32_t len = strlen(value);
	if ((s[strspn(s, "0123456789abcdefABCDEF")] != 0) || (len == 0) || (len > 2))
		{
			cfg.gbox_my_vers = GBOX_MY_VERS_DEF;
		}
		else
		{
			cfg.gbox_my_vers = a2i(value,1);
			return;
		}
	}

	if(cfg.gbox_my_vers != GBOX_MY_VERS_DEF)
	{
		fprintf_conf(f, token, "%02X\n", cfg.gbox_my_vers);
	}
	else if(cfg.http_full_cfg)
		{
			fprintf_conf(f, token, "%02X\n", GBOX_MY_VERS_DEF);
		}
}

static void gbox_my_cpu_api_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		const char *s;
		s=value;
		int32_t len = strlen(value);
	if ((s[strspn(s, "0123456789abcdefABCDEF")] != 0) || (len == 0) || (len > 2))
		{
			cfg.gbox_my_cpu_api = GBOX_MY_CPU_API_DEF;
		}
		else
		{
			cfg.gbox_my_cpu_api = a2i(value,1);
			return;
		}
	}
	
	if(cfg.gbox_my_cpu_api != GBOX_MY_CPU_API_DEF)
	{
		fprintf_conf(f, token, "%02X\n", cfg.gbox_my_cpu_api);
	}
	else if(cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%02X\n", GBOX_MY_CPU_API_DEF); }
}

static void gbox_dest_peers_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if (value)
	{
		char *ptr1, *saveptr1 = NULL;
		const char *s;
		memset(cfg.gbox_dest_peers, 0, sizeof(cfg.gbox_dest_peers));
		int n = 0;
		for (ptr1 = strtok_r(value, ",", &saveptr1); (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1))
		{
			s=trim(ptr1);
			if ((n < GBOX_MAX_DEST_PEERS) && (s[strspn(s, "0123456789abcdefABCDEF")] == 0))
			{ cfg.gbox_dest_peers[n++] = a2i(trim(ptr1), strlen(trim(ptr1))); }
		}
		cfg.gbox_dest_peers_num = n;
		return;
	}
	if ((cfg.gbox_dest_peers_num > 0) && cfg.gbox_save_gsms)
	{
		value = mk_t_gbox_dest_peers();
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

static void gbox_msg_txt_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	int len = 0;
	if (value)
	{
		len = strlen(value);
		if (len > GBOX_MAX_MSG_TXT) { len = GBOX_MAX_MSG_TXT; }
		cs_strncpy(cfg.gbox_msg_txt,value, len+1);
		return;
	}
	if ((cfg.gbox_msg_txt[0]!='\0') && cfg.gbox_save_gsms)
	{
		fprintf_conf(f, token, "%s\n", cfg.gbox_msg_txt);
	}
}

static bool gbox_should_save_fn(void *UNUSED(var))
{
	return cfg.gbox_port[0];
}

static const struct config_list gbox_opts[] =
{
	DEF_OPT_SAVE_FUNC(gbox_should_save_fn),
	DEF_OPT_FUNC("port"		, OFS(gbox_port)	, gbox_port_fn),
	DEF_OPT_STR("hostname"		, OFS(gbox_hostname)	, NULL),
	DEF_OPT_FUNC("my_password"	, OFS(gbox_password)	, gbox_password_fn ),
	DEF_OPT_UINT32("gbox_reconnect"	, OFS(gbox_reconnect)	, DEFAULT_GBOX_RECONNECT),
	DEF_OPT_FUNC("my_vers"		, OFS(gbox_my_vers)	, gbox_my_vers_fn),
	DEF_OPT_FUNC("my_cpu_api"	, OFS(gbox_my_cpu_api)	, gbox_my_cpu_api_fn),
	DEF_OPT_UINT8("ccc_reshare"	, OFS(ccc_reshare)	, 0),
	DEF_OPT_UINT8("gsms_disable"	, OFS(gsms_dis)		, 1),
	DEF_OPT_UINT8("dis_attack_txt"	, OFS(dis_attack_txt)	, 0),
	DEF_OPT_UINT8("log_hello"	, OFS(log_hello)	, 1),
	DEF_OPT_STR("tmp_dir"		, OFS(gbox_tmp_dir)	, NULL ),
	DEF_OPT_FUNC("ignore_peer"	, OFS(gbox_ignored_peer), gbox_ignored_peer_fn ),
	DEF_OPT_FUNC("accept_remm_peer"	, OFS(accept_remm_peer), accept_remm_peer_fn ),
	DEF_OPT_FUNC("block_ecm"	, OFS(gbox_block_ecm)	, gbox_block_ecm_fn ),
	DEF_OPT_FUNC("proxy_card"	, OFS(gbox_proxy_card)	, gbox_proxy_card_fn ),
	DEF_OPT_UINT8("gbox_save_gsms"	, OFS(gbox_save_gsms)		, 0),
 	DEF_OPT_UINT8("gbox_msg_type"	, OFS(gbox_msg_type)		, 0),
 	DEF_OPT_FUNC("gbox_dest_peers"	, OFS(gbox_dest_peers)		, gbox_dest_peers_fn ),
 	DEF_OPT_FUNC("gbox_msg_txt"		, OFS(gbox_msg_txt)			, gbox_msg_txt_fn ),
	DEF_LAST_OPT
};
#else
static const struct config_list gbox_opts[] = { DEF_LAST_OPT };
#endif

#ifdef HAVE_DVBAPI
extern const char *boxdesc[];

static void dvbapi_boxtype_fn(const char *token, char *value, void *UNUSED(setting), FILE *f)
{
	if(value)
	{
		int i;
		cfg.dvbapi_boxtype = 0;
		for(i = 1; i <= BOXTYPES; i++)
		{
			if(streq(value, boxdesc[i]))
			{
				cfg.dvbapi_boxtype = i;
				break;
			}
		}
		return;
	}
	if(cfg.dvbapi_boxtype)
		{ fprintf_conf(f, token, "%s\n", boxdesc[cfg.dvbapi_boxtype]); }
}

static void dvbapi_services_fn(const char *UNUSED(token), char *value, void *UNUSED(setting), FILE *UNUSED(f))
{
	if(value)
		{ chk_services(value, &cfg.dvbapi_sidtabs); }
	// THIS OPTION IS NOT SAVED
}

extern struct s_dvbapi_priority *dvbapi_priority;

static void dvbapi_caidtab_fn(const char *UNUSED(token), char *caidasc, void *UNUSED(setting), long cmd, FILE *UNUSED(f))
{
	char *ptr1, *ptr3, *saveptr1 = NULL;
	if(!caidasc)
		{ return; }
	char type = (char)cmd;
	for(ptr1 = strtok_r(caidasc, ",", &saveptr1); (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1))
	{
		uint32_t caid, prov;
		if((ptr3 = strchr(trim(ptr1), ':')))
			{ * ptr3++ = '\0'; }
		else
			{ ptr3 = ""; }
		if(((caid = a2i(ptr1, 2)) | (prov = a2i(ptr3, 3))))
		{
			struct s_dvbapi_priority *entry;
			if(!cs_malloc(&entry, sizeof(struct s_dvbapi_priority)))
				{ return; }
			entry->caid = caid;
			if(type == 'd')
			{
				char tmp1[5];
				snprintf(tmp1, sizeof(tmp1), "%04X", (uint)prov);
				int32_t cw_delay = strtol(tmp1, NULL, 10);
				entry->delay = cw_delay;
			}
			else
			{
				entry->provid = prov;
			}
			entry->type = type;
			entry->next = NULL;
			if(!dvbapi_priority)
			{
				dvbapi_priority = entry;
			}
			else
			{
				struct s_dvbapi_priority *p;
				for(p = dvbapi_priority; p->next != NULL; p = p->next)
					{ ; }
				p->next = entry;
			}
		}
	}
	// THIS OPTION IS NOT SAVED
}

static bool dvbapi_should_save_fn(void *UNUSED(var))
{
	return cfg.dvbapi_enabled;
}

static const struct config_list dvbapi_opts[] =
{
	DEF_OPT_SAVE_FUNC(dvbapi_should_save_fn),
	DEF_OPT_INT8("enabled"		, OFS(dvbapi_enabled),		0),
	DEF_OPT_INT8("au"		, OFS(dvbapi_au),		0),
	DEF_OPT_INT8("pmt_mode"		, OFS(dvbapi_pmtmode),		0),
	DEF_OPT_INT8("request_mode"	, OFS(dvbapi_requestmode),	0),
	DEF_OPT_INT32("listen_port"	, OFS(dvbapi_listenport),	0),
	DEF_OPT_INT32("delayer"		, OFS(dvbapi_delayer),		0),
	DEF_OPT_INT8("ecminfo_type"		, OFS(dvbapi_ecminfo_type),	0),
	DEF_OPT_STR("user"		, OFS(dvbapi_usr),		NULL),
	DEF_OPT_INT8("read_sdt"		, OFS(dvbapi_read_sdt),	0),
	DEF_OPT_INT8("write_sdt_prov", OFS(dvbapi_write_sdt_prov),	0),
	DEF_OPT_INT8("extended_cw_api", OFS(dvbapi_extended_cw_api),	0),
	DEF_OPT_INT8("extended_cw_pids", OFS(dvbapi_extended_cw_pids),	64), // pid limiter
	DEF_OPT_FUNC("boxtype"		, OFS(dvbapi_boxtype),		dvbapi_boxtype_fn),
	DEF_OPT_FUNC("services"		, OFS(dvbapi_sidtabs.ok),	dvbapi_services_fn),
	// OBSOLETE OPTIONS
	DEF_OPT_FUNC_X("priority"	, 0, dvbapi_caidtab_fn,		'p'),
	DEF_OPT_FUNC_X("ignore"		, 0, dvbapi_caidtab_fn,		'i'),
	DEF_OPT_FUNC_X("cw_delay"	, 0, dvbapi_caidtab_fn,		'd'),
	DEF_LAST_OPT
};
#else
static const struct config_list dvbapi_opts[] = { DEF_LAST_OPT };
#endif

#ifdef LCDSUPPORT
static void lcd_fixups_fn(void *UNUSED(var))
{
	if(cfg.lcd_write_intervall < 5) { cfg.lcd_write_intervall = 5; }
}

static bool lcd_should_save_fn(void *UNUSED(var))
{
	return cfg.enablelcd;
}

static const struct config_list lcd_opts[] =
{
	DEF_OPT_SAVE_FUNC(lcd_should_save_fn),
	DEF_OPT_FIXUP_FUNC(lcd_fixups_fn),
	DEF_OPT_INT8("enablelcd"		, OFS(enablelcd),		0),
	DEF_OPT_STR("lcd_outputpath"		, OFS(lcd_output_path),		NULL),
	DEF_OPT_INT32("lcd_hideidle"		, OFS(lcd_hide_idle),		0),
	DEF_OPT_INT32("lcd_writeintervall"	, OFS(lcd_write_intervall),	10),
	DEF_LAST_OPT
};
#else
static const struct config_list lcd_opts[] = { DEF_LAST_OPT };
#endif

static const struct config_sections oscam_conf[] =
{
	{ "global",	global_opts }, // *** MUST BE FIRST ***
	{ "anticasc",	anticasc_opts },
	{ "cache",	cache_opts },
	{ "lcd",	lcd_opts },
	{ "camd33",	camd33_opts },
	{ "cs357x",	camd35_opts },
	{ "cs378x",	cs378x_opts },
	{ "newcamd",	newcamd_opts },
	{ "radegast",	radegast_opts },
	{ "serial",	serial_opts },
	{ "gbox",	gbox_opts },
	{ "cccam",	cccam_opts },
	{ "pandora",	pandora_opts },
	{ "scam",	scam_opts },
	{ "streamrelay",	streamrelay_opts },
	{ "dvbapi",	dvbapi_opts },
	{ "monitor",	monitor_opts },
	{ "webif",	webif_opts },
	{ NULL, NULL }
};

void config_set(char *section, const char *token, char *value)
{
	config_set_value(oscam_conf, section, token, value, &cfg);
}

void config_free(void)
{
	config_sections_free(oscam_conf, &cfg);
	caidvaluetab_clear(&cfg.ftimeouttab);
	caidtab_clear(&cfg.double_check_caid);
	ftab_clear(&cfg.disablecrccws_only_for);
#ifdef WITH_LB
	caidvaluetab_clear(&cfg.lb_retrylimittab);
	caidvaluetab_clear(&cfg.lb_nbest_readers_tab);
	caidtab_clear(&cfg.lb_noproviderforcaid);
#endif
#ifdef CS_CACHEEX
	caidvaluetab_clear(&cfg.cacheex_mode1_delay_tab);
	cecspvaluetab_clear(&cfg.cacheex_wait_timetab);
#endif
#ifdef CW_CYCLE_CHECK
	caidtab_clear(&cfg.cwcycle_check_caidtab);
#endif
}

int32_t init_config(void)
{
	FILE *fp;

	if(config_enabled(WEBIF))
	{
		fp = open_config_file(cs_conf);
	}
	else
	{
		fp = open_config_file_or_die(cs_conf);
	}

	const struct config_sections *cur_section = oscam_conf; // Global
	char *token;
	
	config_sections_set_defaults(oscam_conf, &cfg);

	if(!fp)
	{
		// no oscam.conf but webif is included in build, set it up for lan access and tweak defaults
#ifdef WEBIF
		cfg.http_port = DEFAULT_HTTP_PORT;
		char *default_allowed;
		if ((default_allowed = cs_strdup(DEFAULT_HTTP_ALLOW)))
		{
			chk_iprange(default_allowed, &cfg.http_allowed);
			free(default_allowed);
		}
#endif
		NULLFREE(cfg.logfile);
		cfg.logtostdout = 1;
#ifdef HAVE_DVBAPI
		cfg.dvbapi_enabled = 1;
#endif
		return 0;
	}

	if(!cs_malloc(&token, MAXLINESIZE))
		{ return 1; }

	int line = 0;
	int valid_section = 1;
	while(fgets(token, MAXLINESIZE, fp))
	{
		++line;
		int len = strlen(trim(token));
		if(len < 3)  // a=b or [a] are at least 3 chars
			{ continue; }
		if(token[0] == '#')  // Skip comments
			{ continue; }
		if(token[0] == '[' && token[len - 1] == ']')
		{
			token[len - 1] = '\0';
			valid_section = 0;
			const struct config_sections *newconf = config_find_section(oscam_conf, token + 1);
			if(config_section_is_active(newconf) && cur_section)
			{
				config_list_apply_fixups(cur_section->config, &cfg);
				cur_section = newconf;
				valid_section = 1;
			}
			if(!newconf)
			{
				fprintf(stderr, "WARNING: %s line %d unknown section [%s].\n",
						cs_conf, line, token + 1);
				continue;
			}
			if(!config_section_is_active(newconf))
			{
				fprintf(stderr, "WARNING: %s line %d section [%s] is ignored (support not compiled in).\n",
						cs_conf, line, newconf->section);
			}
			continue;
		}

		if(!valid_section)
			{ continue; }
		char *value = strchr(token, '=');
		if(!value)  // No = found, well go on
			{ continue; }
		*value++ = '\0';
		char *tvalue = trim(value);
		char *ttoken = trim(strtolower(token));
		if(cur_section && !config_list_parse(cur_section->config, ttoken, tvalue, &cfg))
		{
			fprintf(stderr, "WARNING: %s line %d section [%s] contains unknown setting '%s=%s'\n",
					cs_conf, line, cur_section->section, ttoken, tvalue);
		}
	}
	NULLFREE(token);
	fclose(fp);
	if(cur_section) { config_list_apply_fixups(cur_section->config, &cfg); }
	return 0;
}

int32_t write_config(void)
{
	FILE *f = create_config_file(cs_conf);
	if(!f)
		{ return 1; }
	config_sections_save(oscam_conf, f, &cfg);
	return flush_config_file(f, cs_conf);
}
