/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014 Tanguy Pruvot
 * Copyright 2018 AtomMiner
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <cpuminer-config.h>
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <execinfo.h>

#include <curl/curl.h>
#include <jansson.h>
#include <openssl/sha.h>

#ifdef _MSC_VER
#include <windows.h>
#include <stdint.h>
#else
#include <errno.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif

#ifndef WIN32
#include <sys/resource.h>
#include <fcntl.h>
#include <termios.h>
#endif

#include "miner.h"

#ifdef WIN32
#include "compat/winansi.h"
BOOL WINAPI ConsoleHandler(DWORD);
#endif
#ifdef _MSC_VER
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#endif

#define LP_SCANTIME		60

#ifndef min
#define min(a,b) (a>b ? b : a)
#define max(a,b) (a<b ? b : a)
#endif

enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands cmd;
	struct thr_info *thr;
	union {
		struct work *work;
	} u;
};

bool opt_debug = false;
bool opt_debug_diff = false;
bool opt_protocol = false;
bool opt_benchmark = false;
bool opt_redirect = true;
bool opt_showdiff = false;
bool opt_extranonce = true;
bool use_colors = true;
static bool opt_background = false;
bool opt_quiet = false;
int opt_maxlograte = 5;
bool opt_randomize = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
int opt_timeout = 1200; //
static int opt_scantime = 5;
int opt_n_threads = 2;
int64_t opt_affinity = -1L;
int opt_priority = 0;
int num_cpus;
char *rpc_url;
char *rpc_userpass;
char *rpc_user, *rpc_pass;
char *short_url = NULL;
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
bool stratum_need_reset = false;
struct work_restart *work_restart = NULL;
struct stratum_ctx stratum;
bool aes_ni_supported = false;
double opt_diff_factor = 1.;
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;

uint32_t solved_count = 0L;
uint32_t accepted_count = 0L;
uint32_t rejected_count = 0L;
double *thr_hashrates;
uint64_t global_hashrate = 0;
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
uint64_t net_blocks = 0;
// conditional mining
bool conditional_state[MAX_CPUS] = { 0 };
double opt_max_temp = 0.0;
double opt_max_diff = 0.0;
double opt_max_rate = 0.0;

uint32_t opt_work_size = 0; /* default */
char *opt_api_allow = NULL;
int opt_api_remote = 0;
int opt_api_listen = 4048; /* 0 to disable */

struct timeval start_time;
double best_accepted = 0;
double last_accepted = 0;

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};
#endif

static char const usage[] = "\
Usage: " PACKAGE_NAME " [OPTIONS]\n\
Options:\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
  -t, --threads=N       number of miner threads (default: number of processors)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
  -T, --timeout=N       timeout for stratum (default: 300 seconds)\n\
  -V, --version         display version information and exit\n\
  -h, --help            display this help text and exit\n\
";


static char const short_options[] =
    "hm:n:p:Px:qr:R:s:t:T:o:u:V";

static struct option const options[] = {
	{ "help", 0, NULL, 'h' },
	{ "pass", 1, NULL, 'p' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "threads", 1, NULL, 't' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ "version", 0, NULL, 'V' },
	{ 0, 0, 0, 0 }
};

static struct work g_work = {{ 0 }};
static time_t g_work_time = 0;
static pthread_mutex_t g_work_lock;


#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>

static inline void drop_policy(void)
{
	struct sched_param param;
	param.sched_priority = 0;
#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

#ifdef __BIONIC__
#define pthread_setaffinity_np(tid,sz,s) {} /* only do process affinity */
#endif

static void affine_to_cpu_mask(int id, unsigned long mask) {
	cpu_set_t set;
	CPU_ZERO(&set);
	for (uint8_t i = 0; i < num_cpus; i++) {
		// cpu mask
		if (mask & (1UL<<i)) { CPU_SET(i, &set); }
	}
	if (id == -1) {
		// process affinity
		sched_setaffinity(0, sizeof(&set), &set);
	} else {
		// thread only
		pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
	}
}

#elif defined(WIN32) /* Windows */
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, unsigned long mask) {
	if (id == -1)
		SetProcessAffinityMask(GetCurrentProcess(), mask);
	else
		SetThreadAffinityMask(GetCurrentThread(), mask);
}
#else
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, unsigned long mask) { }
#endif

void proper_exit(int reason)
{
#ifdef WIN32
	if (opt_background) {
		HWND hcon = GetConsoleWindow();
		if (hcon) {
			// unhide parent command line windows
			ShowWindow(hcon, SW_SHOWMINNOACTIVE);
		}
	}
#endif
	exit(reason);
}

static inline void work_free(struct work *w)
{
	if (w->job_id) FREE(w->job_id);
}

static inline void work_copy(struct work *dest, const struct work *src)
{
	memcpy(dest, src, sizeof(struct work));
    if (src->job_id)
        dest->job_id = strdup(src->job_id);
}

/* compute nbits to get the network diff */
static void calc_network_diff(struct work *work)
{
    uint32_t nbits = swab32(work->data[18]);
	uint32_t bits = (nbits & 0xffffff);
	int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28

	double d = (double)0x0000ffff / (double)bits;
	for (int m=shift; m < 29; m++) d *= 256.0;
	for (int m=29; m < shift; m++) d /= 256.0;
	net_diff = d;
}

static bool work_decode(const json_t *val, struct work *work)
{
	int i;
	int data_size = 128, target_size = sizeof(work->target);
	int adata_sz = 32, atarget_sz = ARRAY_SIZE(work->target);

	if (unlikely(!jobj_binary(val, "data", work->data, data_size))) {
		applog(LOG_ERR, "JSON invalid data");
		goto err_out;
	}
	if (unlikely(!jobj_binary(val, "target", work->target, target_size))) {
		applog(LOG_ERR, "JSON invalid target");
		goto err_out;
	}
	
	char s[256];
    bin2hex(s, (const uint8_t*)work->target, 32);
	printf("work_decode target1: %s", s);

	for (i = 0; i < adata_sz; i++)
		work->data[i] = le32dec(work->data + i);
	for (i = 0; i < atarget_sz; i++)
		work->target[i] = le32dec(work->target + i);

    bin2hex(s, (const uint8_t*)work->target, 32);
	printf("work_decode target2: %s", s);

	work->targetdiff = target_to_diff(work->target);

	stratum_diff = work->targetdiff;

	return true;

err_out:
	return false;
}

#define YES "yes!"
#define YAY "yay!!!"
#define BOO "booooo"

static int share_result(int result, struct work *work, const char *reason)
{
	const char *flag;
	char suppl[32] = { 0 };
	char s[345];
	double hashrate;
	double sharediff = work ? work->sharediff : stratum.sharediff;
	int i;

	hashrate = 0.;
	pthread_mutex_lock(&stats_lock);
	for (i = 0; i < opt_n_threads; i++)
		hashrate += thr_hashrates[i];
	result ? accepted_count++ : rejected_count++;
	pthread_mutex_unlock(&stats_lock);

	global_hashrate = (uint64_t) hashrate;

	if (!net_diff || sharediff < net_diff) {
		flag = use_colors ?
			(result ? CL_GRN YES : CL_RED BOO)
		:	(result ? "(" YES ")" : "(" BOO ")");
	} else {
		solved_count++;
		flag = use_colors ?
			(result ? CL_GRN YAY : CL_RED BOO)
		:	(result ? "(" YAY ")" : "(" BOO ")");
	}

	if (opt_showdiff)
		sprintf(suppl, "diff %.3f", sharediff);
	else // accepted percent
		sprintf(suppl, "%.2f%%", 100. * accepted_count / (accepted_count + rejected_count));


    sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", hashrate / 1000.0);
    applog(LOG_NOTICE, "accepted: %lu/%lu (%s), %s kH/s %s",
        accepted_count, accepted_count + rejected_count,
        suppl, s, flag);

	if (reason) {
		applog(LOG_WARNING, "reject reason: %s", reason);
		if (0 && strncmp(reason, "low difficulty share", 20) == 0) {
			opt_diff_factor = (opt_diff_factor * 2.0) / 3.0;
			applog(LOG_WARNING, "factor reduced to : %0.2f", opt_diff_factor);
			return 0;
		}
	}
	return 1;
}

static bool submit_upstream_work(CURL *curl, struct work *work)
{
	char s[JSON_BUF_LEN];

    char *hdr = abin2hex(work->data, 100);

    snprintf(s, JSON_BUF_LEN,
            "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\"], \"id\":4}",
            rpc_user, work->job_id, hdr);
    //applog(LOG_DEBUG, "%s", s);
    FREE(hdr);

    stratum.sharediff = work->sharediff;

    if (unlikely(!stratum_send_line(&stratum, s))) {
        applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
        return false;
    }

    return true;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	uchar merkle_root[64] = { 0 };
	int i, headersize = 0;

	pthread_mutex_lock(&sctx->work_lock);

    FREE(work->job_id);
    work->job_id = strdup(sctx->job.job_id);
    work->restart = true;
    memcpy(work->data, sctx->job.header, 100);
    work_set_target(work, sctx->next_diff / opt_diff_factor);

    // randomize 128bit nonce field
    uint32_t r1 = rand();
    uint32_t r2 = rand();
    uint32_t r3 = rand();
    memcpy(&work->data[21], &r1, 4);
    memcpy(&work->data[22], &r2, 4);
    memcpy(&work->data[23], &r3, 4);

    pthread_mutex_unlock(&sctx->work_lock);
}

extern int atomminer_scanhash_sha3(int thr_id, struct work *work, uint64_t *hashes_done);

static void workio_cmd_free(struct workio_cmd *wc)
{
    if (!wc)
        return;

    switch (wc->cmd) {
    case WC_SUBMIT_WORK:
        work_free(wc->u.work);
        FREE(wc->u.work);
        break;
    default: /* do nothing */
        break;
    }

    memset(wc, 0, sizeof(*wc)); /* poison */
    FREE(wc);
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
    struct workio_cmd *wc;

    /* fill out work request message */
    wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
    if (!wc)
        return false;

    wc->u.work = (struct work*) malloc(sizeof(*work_in));
    if (!wc->u.work)
        goto err_out;

    wc->cmd = WC_SUBMIT_WORK;
    wc->thr = thr;
    work_copy(wc->u.work, work_in);

    submit_upstream_work(&stratum.curl, work_in);

    /* send solution to workio thread */
    if (!tq_push(thr_info[work_thr_id].q, wc))
        goto err_out;

    return true;

err_out:
    workio_cmd_free(wc);
    return false;
}

static void *miner_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	int thr_id = mythr->id;
	struct work work;
	uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
	time_t tm_rate_log = 0;
	time_t firstwork_time = 0;
	char s[16];

	memset(&work, 0, sizeof(work));

    {
		int prio = 0;
#ifndef WIN32
		prio = 18;
		switch (opt_priority) {
			case 1:
				prio = 5;
				break;
			case 2:
				prio = 0;
				break;
			case 3:
				prio = -5;
				break;
			case 4:
				prio = -10;
				break;
			case 5:
				prio = -15;
		}
		if (opt_debug)
			applog(LOG_DEBUG, "Thread %d priority %d (nice %d)",
				thr_id,	opt_priority, prio);
#endif
		setpriority(PRIO_PROCESS, 0, prio);
		if (opt_priority == 0) {
			drop_policy();
		}
	}

	if (num_cpus > 1) {
		if (opt_affinity == -1 && opt_n_threads > 1) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu %d (mask %x)", thr_id,
						thr_id % num_cpus, (1 << (thr_id % num_cpus)));
			affine_to_cpu_mask(thr_id, 1UL << (thr_id % num_cpus));
		} else if (opt_affinity != -1L) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu mask %x", thr_id,
						opt_affinity);
			affine_to_cpu_mask(thr_id, (unsigned long)opt_affinity);
		}
	}
	
	srand(time(NULL));

	while (1) {
		uint64_t hashes_done;
		struct timeval tv_start, tv_end, diff;
        bool regen_work = true;
		int wkcmp_offset = 0;
        int nonce_oft = 84;
		int wkcmp_sz = nonce_oft;
		int rc = 0;

		uint32_t *nonceptr = (uint32_t*) (((char*)work.data) + nonce_oft);

        while(!stratum.job.job_id){
            sleep(1);
        }

        if (regen_work) {
            if(opt_debug)
                applog(LOG_DEBUG, "Generating new Work");
            stratum_gen_work(&stratum, &g_work);
        }

        if (!g_work.data[2]) {
            sleep(1);
            continue;
        }

        pthread_mutex_lock(&g_work_lock);
		
        work_free(&work);
        work_copy(&work, &g_work);
        pthread_mutex_unlock(&g_work_lock);
		work_restart[thr_id].restart = 0;

        if (!work.data[2]) {
			sleep(1);
			continue;
		}

		hashes_done = 0;
		gettimeofday((struct timeval *) &tv_start, NULL);

		if (firstwork_time == 0)
			firstwork_time = time(NULL);

        rc = atomminer_scanhash_sha3(thr_id, &work, &hashes_done);

		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);
		if (diff.tv_usec || diff.tv_sec) {
			pthread_mutex_lock(&stats_lock);
			thr_hashrates[thr_id] =
				hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
			pthread_mutex_unlock(&stats_lock);
		}
		if (!opt_quiet && (time(NULL) - tm_rate_log) > opt_maxlograte) {
				sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.2f" : "%.2f",
                        thr_hashrates[thr_id] / 1e3);
                applog(LOG_INFO, "CPU%d: %s kH/s - A/R %lu/%lu", thr_id, s, accepted_count, rejected_count);
			tm_rate_log = time(NULL);
		}

        if (rc)
            submit_upstream_work(&stratum.curl, &work);
	}

out:
	tq_freeze(mythr->q);

	return NULL;
}

void restart_threads(void)
{
	int i;

	for (i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
}

static bool stratum_handle_response(char *buf)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	bool ret = false;
	bool valid = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");

	if (!id_val || json_is_null(id_val))
		goto out;

    if (!res_val || json_integer_value(id_val) < 4)
        goto out;
    valid = json_is_true(res_val);
    share_result(valid, NULL, err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);

	ret = true;

out:
	if (val)
		json_decref(val);

	return ret;
}

static void *stratum_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	char *s;

	stratum.url = (char*) tq_pop(mythr->q, NULL);
	if (!stratum.url)
		goto out;
	applog(LOG_INFO, "Starting Stratum on %s", stratum.url);

	while (1) {
		int failures = 0;

		if (stratum_need_reset) {
			stratum_need_reset = false;
			stratum_disconnect(&stratum);
			if (strcmp(stratum.url, rpc_url)) {
				FREE(stratum.url);
				stratum.url = strdup(rpc_url);
				applog(LOG_BLUE, "Connection changed to %s", short_url);
			} else if (!opt_quiet) {
				applog(LOG_DEBUG, "Stratum connection reset");
			}
		}

		while (!stratum.curl) {
			pthread_mutex_lock(&g_work_lock);
			g_work_time = 0;
			pthread_mutex_unlock(&g_work_lock);
			restart_threads();

			if (!stratum_connect(&stratum, stratum.url)
                    //|| !stratum_subscribe(&stratum)
					|| !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
				stratum_disconnect(&stratum);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					applog(LOG_ERR, "...terminating workio thread");
					tq_push(thr_info[work_thr_id].q, NULL);
					goto out;
				}
				if (!opt_benchmark)
					applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
			}

		}

		if (stratum.job.job_id &&
			(!g_work_time || strcmp(stratum.job.job_id, g_work.job_id)) )
		{
			pthread_mutex_lock(&g_work_lock);
			stratum_gen_work(&stratum, &g_work);
			time(&g_work_time);
			pthread_mutex_unlock(&g_work_lock);

            restart_threads();
		}

		if (!stratum_socket_full(&stratum, opt_timeout)) {
			applog(LOG_ERR, "Stratum connection timeout");
            g_work.data[2] = 0;
			s = NULL;
		} else
			s = stratum_recv_line(&stratum);
		if (!s) {
			stratum_disconnect(&stratum);
			applog(LOG_ERR, "Stratum connection interrupted");
            g_work.data[2] = 0;
			continue;
		}
		if (!stratum_handle_method(&stratum, s))
			stratum_handle_response(s);
		FREE(s);
	}
out:
	return NULL;
}

static void show_version_and_exit(void)
{
	printf(" built "
#ifdef _MSC_VER
	 "with VC++ %d", msver());
#elif defined(__GNUC__)
	 "with GCC ");
	printf("%d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif
	printf(" the " __DATE__ "\n");

	// Note: if compiled with cpu opts (instruction sets),
	// the binary is no more compatible with older ones!
	printf(" compiled for"
#if defined(__ARM_NEON__)
		" ARM NEON"
#elif defined(__AVX2__)
		" AVX2"
#elif defined(__AVX__)
		" AVX"
#elif defined(__XOP__)
		" XOP"
#elif defined(__SSE4_1__)
		" SSE4"
#elif defined(_M_X64) || defined(__x86_64__)
		" x64"
#elif defined(_M_IX86) || defined(__x86__)
		" x86"
#else
		" general use"
#endif
		"\n");

	printf(" config features:"
#if defined(USE_ASM) && defined(__i386__)
		" i386"
#endif
#if defined(USE_ASM) && defined(__x86_64__)
		" x86_64"
#endif
#if defined(USE_ASM) && (defined(__i386__) || defined(__x86_64__))
		" SSE2"
#endif
#if defined(__x86_64__) && defined(USE_XOP)
		" XOP"
#endif
#if defined(__x86_64__) && defined(USE_AVX)
		" AVX"
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
		" AVX2"
#endif
#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)
		" ARM"
#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
	defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
	defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
	defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
	defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || \
	defined(__ARM_ARCH_7__) || \
	defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
	defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
		" ARMv5E"
#endif
#if defined(__ARM_NEON__)
		" NEON"
#endif
#endif
		"\n\n");
	/* dependencies versions */
	printf("%s\n", curl_version());
#ifdef JANSSON_VERSION
	printf("jansson/%s ", JANSSON_VERSION);
#endif
#ifdef PTW32_VERSION
	printf("pthreads/%d.%d.%d.%d ", PTW32_VERSION);
#endif
	printf("\n");
	exit(0);
}

static void show_usage_and_exit(int status)
{
	if (status)
		fprintf(stderr, "Try `" PACKAGE_NAME " --help' for more information.\n");
	else
		printf(usage);
	exit(status);
}

static void strhide(char *s)
{
	if (*s) *s++ = 'x';
	while (*s) *s++ = '\0';
}

void parse_arg(int key, char *arg)
{
	char *p;
    int v;

	switch(key) {
    case 'D':
		opt_debug = true;
		break;
	case 'p':
		FREE(rpc_pass);
		rpc_pass = strdup(arg);
		strhide(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 't':
		v = atoi(arg);
		if (v < 0 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_n_threads = v;
		break;
	case 'u':
		FREE(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'V':
		show_version_and_exit();
	case 'h':
		show_usage_and_exit(0);
	default:
		show_usage_and_exit(1);
	}
}

void parse_config(json_t *config, char *ref)
{
	int i;
	json_t *val;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;

		val = json_object_get(config, options[i].name);
		if (!val)
			continue;
		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s);
			FREE(s);
		}
		else if (options[i].has_arg && json_is_integer(val)) {
			char buf[16];
			sprintf(buf, "%d", (int)json_integer_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (options[i].has_arg && json_is_real(val)) {
			char buf[16];
			sprintf(buf, "%f", json_real_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (!options[i].has_arg) {
			if (json_is_true(val))
				parse_arg(options[i].val, "");
		}
		else
			applog(LOG_ERR, "JSON option %s invalid",
			options[i].name);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
#if HAVE_GETOPT_LONG
		key = getopt_long(argc, argv, short_options, options, NULL);
#else
		key = getopt(argc, argv, short_options);
#endif
		if (key < 0)
			break;

		parse_arg(key, optarg);
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unsupported non-option argument -- '%s'\n",
			argv[0], argv[optind]);
		show_usage_and_exit(1);
	}
}

#ifndef WIN32
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		applog(LOG_INFO, "SIGINT received, exiting");
		proper_exit(0);
		break;
	case SIGTERM:
		applog(LOG_INFO, "SIGTERM received, exiting");
		proper_exit(0);
		break;
	}
}
#else
BOOL WINAPI ConsoleHandler(DWORD dwType)
{
	switch (dwType) {
	case CTRL_C_EVENT:
		applog(LOG_INFO, "CTRL_C_EVENT received, exiting");
		proper_exit(0);
		break;
	case CTRL_BREAK_EVENT:
		applog(LOG_INFO, "CTRL_BREAK_EVENT received, exiting");
		proper_exit(0);
		break;
	default:
		return false;
	}
	return true;
}
#endif

static int thread_create(struct thr_info *thr, void* func)
{
	int err = 0;
	pthread_attr_init(&thr->attr);
	err = pthread_create(&thr->pth, &thr->attr, func, thr);
	pthread_attr_destroy(&thr->attr);
	return err;
}

static void show_credits()
{
	printf("** " PACKAGE_NAME " " PACKAGE_VERSION " by atom@atomminer.com **\n");
    printf("BTC donation address: 1QGnF8SGi8BuKdDVaKKk9kGX8N3VfUFtLx\n\n");
}

void get_defconfig_path(char *out, size_t bufsize, char *argv0);

// based in http://www.linuxjournal.com/article/6391?page=0,0
void atom_sighandler(int sig, struct sigcontext ctx) {

  void *trace[16];
  char **messages = (char **)NULL;
  int i, trace_size = 0;

  //if (sig == SIGSEGV)
  //  printf("Got signal %d, faulty address is %p"
  //         , sig, ctx.cr2);
  //else
  //  printf("Got signal %d\n", sig);

  trace_size = backtrace(trace, 16);
  messages = backtrace_symbols(trace, trace_size);
  printf("Execution path:\n");
  for (i=1; i<trace_size; ++i)
  {
    printf("  #%d %s\n", i, messages[i]);

    char syscom[256];
    sprintf(syscom,"addr2line %p -e atomminer", trace[i]); //last parameter is the name of this app
    system(syscom);
  }

  exit(0);
}

#define   RD_EOF   -1
#define   RD_EIO   -2

static inline int rd(const int fd)
{
    unsigned char   buffer[4];
    ssize_t         n;

    while (1) {

        n = read(fd, buffer, 1);
        if (n > (ssize_t)0)
            return buffer[0];

        else
        if (n == (ssize_t)0)
            return RD_EOF;

        else
        if (n != (ssize_t)-1)
            return RD_EIO;

        else
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            return RD_EIO;
    }
}

static inline int wr(const int fd, const char *const data, const size_t bytes)
{
    const char       *head = data;
    const char *const tail = data + bytes;
    ssize_t           n;

    while (head < tail) {

        n = write(fd, head, (size_t)(tail - head));
        if (n > (ssize_t)0)
            head += n;

        else
        if (n != (ssize_t)-1)
            return EIO;

        else
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            return errno;
    }

    return 0;
}

int cursor_position(const int tty, int *const rowptr, int *const colptr)
{
    struct termios  saved, temporary;
    int             retval, result, rows, cols, saved_errno;

    /* Bad tty? */
    if (tty == -1)
        return ENOTTY;

    saved_errno = errno;

    /* Save current terminal settings. */
    do {
        result = tcgetattr(tty, &saved);
    } while (result == -1 && errno == EINTR);
    if (result == -1) {
        retval = errno;
        errno = saved_errno;
        return retval;
    }

    /* Get current terminal settings for basis, too. */
    do {
        result = tcgetattr(tty, &temporary);
    } while (result == -1 && errno == EINTR);
    if (result == -1) {
        retval = errno;
        errno = saved_errno;
        return retval;
    }

    /* Disable ICANON, ECHO, and CREAD. */
    temporary.c_lflag &= ~ICANON;
    temporary.c_lflag &= ~ECHO;
    temporary.c_cflag &= ~CREAD;

    /* This loop is only executed once. When broken out,
     * the terminal settings will be restored, and the function
     * will return retval to caller. It's better than goto.
    */
    do {

        /* Set modified settings. */
        do {
            result = tcsetattr(tty, TCSANOW, &temporary);
        } while (result == -1 && errno == EINTR);
        if (result == -1) {
            retval = errno;
            break;
        }

        /* Request cursor coordinates from the terminal. */
        retval = wr(tty, "\033[6n", 4);
        if (retval)
            break;

        /* Assume coordinate reponse parsing fails. */
        retval = EIO;

        /* Expect an ESC. */
        result = rd(tty);
        if (result != 27)
            break;

        /* Expect [ after the ESC. */
        result = rd(tty);
        if (result != '[')
            break;

        /* Parse rows. */
        rows = 0;
        result = rd(tty);
        while (result >= '0' && result <= '9') {
            rows = 10 * rows + result - '0';
            result = rd(tty);
        }

        if (result != ';')
            break;

        /* Parse cols. */
        cols = 0;
        result = rd(tty);
        while (result >= '0' && result <= '9') {
            cols = 10 * cols + result - '0';
            result = rd(tty);
        }

        if (result != 'R')
            break;

        /* Success! */

        if (rowptr)
            *rowptr = rows;

        if (colptr)
            *colptr = cols;

        retval = 0;

    } while (0);

    /* Restore saved terminal settings. */
    do {
        result = tcsetattr(tty, TCSANOW, &saved);
    } while (result == -1 && errno == EINTR);
    if (result == -1 && !retval)
        retval = errno;

    /* Done. */
    return retval;
}

extern uint64_t sha3(uint8_t *data);

uint64_t _bswap64(uint64_t a)
{
  a = ((a & 0x00000000000000FFULL) << 56) |
      ((a & 0x000000000000FF00ULL) << 40) |
      ((a & 0x0000000000FF0000ULL) << 24) |
      ((a & 0x00000000FF000000ULL) <<  8) |
      ((a & 0x000000FF00000000ULL) >>  8) |
      ((a & 0x0000FF0000000000ULL) >> 24) |
      ((a & 0x00FF000000000000ULL) >> 40) |
      ((a & 0xFF00000000000000ULL) >> 56);
  return a;
}

int main(int argc, char *argv[]) {
	struct thr_info *thr;
	long flags;
	int i, err;

//    uint32_t endiandata[100];
//    hex2bin((uint8_t*)&endiandata[0], "0000000000000004ac313527db1aa27bd22fe8190789a041818af0eb27c65418b30960f800000770ba2c026f810f818041eb355394a6a48751283111cb0b19ef569fca2e6690d59200000164434611401d1bc5941f835a504eb917120000000000a3c392", 100);
//    uint64_t hash76 = _bswap64(sha3((uint8_t*)&endiandata[0]));

//    hex2bin((uint8_t*)&endiandata[0], "0000000000000000168385d3bbf30db042affadd5d7173b25d865f5b8a8cabb41fd692d900000c2d0cee2212a28c9f7bdac25bfa8055388a6e1db54c6475be6b488da57ba7399374000001645f5f5a041c270d3cffffff7fc6237b3269983c640a192380", 100);
//    sha3((uint8_t*)&endiandata[0]);
//    hex2bin((uint8_t*)&endiandata[0], "0000000000000000168385d3bbf30db042affadd5d7173b25d865f5b8a8cabb41fd692d900000c2d0cee2212a28c9f7bdac25bfa8055388a6e1db54c6475be6b488da57ba7399374000001645f5f5a041c270d3c01000080c6237b3269983c6475ba4480", 100);
//    sha3((uint8_t*)&endiandata[0]);
//    hex2bin((uint8_t*)&endiandata[0], "0000000000000004ca20f2ceba936a39938c8a42a9fd412624be8a6f848d453cb629738f0000109ca0f635dd867c23ae6c8ca18b806a4817e15377333ac53844a250f7ee808710fc000001647ab1b1c11d0c859806b94764799d02477b3032cd42c296bd", 100);
//    sha3((uint8_t*)&endiandata[0]);

    //exit(0);

	gettimeofday(&start_time, NULL);

	struct sigaction sa;

	sa.sa_handler = (void *)atom_sighandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGSEGV, &sa, NULL);
  	sigaction(SIGINT, &sa, NULL);
  	sigaction(SIGILL, &sa, NULL);
  	sigaction(SIGBUS, &sa, NULL);
  	sigaction(SIGSYS, &sa, NULL);
  	sigaction(SIGUSR1, &sa, NULL);
  	sigaction(SIGUSR2, &sa, NULL);

	pthread_mutex_init(&applog_lock, NULL);

	show_credits();

    rpc_url = strdup("stratum+tcp://pool.zenprotocolpool.com:8811");
    //rpc_url = strdup("stratum+tcp://localhost:5143");
    rpc_user = strdup("zen1qnwls4fxx48yz92yyytmzpy5e4pk7qsh69hjgx06z6x4n5n6sp6usuhw3tv");
    rpc_pass = strdup("d=0.1");

#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_cpus = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(num_cpus);
	sysctl(req, 2, &num_cpus, &len, NULL, 0);
#else
	num_cpus = 1;
#endif
	if (num_cpus < 1)
		num_cpus = 1;

	/* parse command line */
	parse_cmdline(argc, argv);

	if (!opt_benchmark && !rpc_url) {
		// try default config file in binary folder
		char defconfig[MAX_PATH] = { 0 };
		get_defconfig_path(defconfig, MAX_PATH, argv[0]);
		if (strlen(defconfig)) {
			if (opt_debug)
				applog(LOG_DEBUG, "Using config %s", defconfig);
			parse_arg('c', defconfig);
			parse_cmdline(argc, argv);
		}
	}

	if (!opt_n_threads)
		opt_n_threads = num_cpus;
	if (!opt_n_threads)
		opt_n_threads = 1;


	if (!opt_benchmark && !rpc_url) {
		fprintf(stderr, "%s: no URL supplied\n", argv[0]);
		show_usage_and_exit(1);
	}

	if (!rpc_userpass) {
		rpc_userpass = (char*) malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

	pthread_mutex_init(&stats_lock, NULL);
	pthread_mutex_init(&g_work_lock, NULL);
	pthread_mutex_init(&stratum.sock_lock, NULL);
	pthread_mutex_init(&stratum.work_lock, NULL);

	flags = !opt_benchmark && strncmp(rpc_url, "https:", 6)
	        ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
	        : CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}

#ifndef WIN32
	if (opt_background) {
		i = fork();
		if (i < 0) exit(1);
		if (i > 0) exit(0);
		i = setsid();
		if (i < 0)
			applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
		i = chdir("/");
		if (i < 0)
			applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
		signal(SIGHUP, signal_handler);
		signal(SIGTERM, signal_handler);
	}
	/* Always catch Ctrl+C */
	signal(SIGINT, signal_handler);
#else
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);
	if (opt_background) {
		HWND hcon = GetConsoleWindow();
		if (hcon) {
			// this method also hide parent command line window
			ShowWindow(hcon, SW_HIDE);
		} else {
			HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
			CloseHandle(h);
			FreeConsole();
		}
	}
	if (opt_priority > 0) {
		DWORD prio = NORMAL_PRIORITY_CLASS;
		switch (opt_priority) {
		case 1:
			prio = BELOW_NORMAL_PRIORITY_CLASS;
			break;
		case 3:
			prio = ABOVE_NORMAL_PRIORITY_CLASS;
			break;
		case 4:
			prio = HIGH_PRIORITY_CLASS;
			break;
		case 5:
			prio = REALTIME_PRIORITY_CLASS;
		}
		SetPriorityClass(GetCurrentProcess(), prio);
	}
#endif
	if (opt_affinity != -1) {
		if (!opt_quiet)
			applog(LOG_DEBUG, "Binding process to cpu mask %x", opt_affinity);
		affine_to_cpu_mask(-1, (unsigned long)opt_affinity);
	}

	work_restart = (struct work_restart*) calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;

	thr_info = (struct thr_info*) calloc(opt_n_threads + 4, sizeof(*thr));
	if (!thr_info)
		return 1;

	thr_hashrates = (double *) calloc(opt_n_threads, sizeof(double));
	if (!thr_hashrates)
		return 1;

    stratum_thr_id = opt_n_threads + 2;
    thr = &thr_info[stratum_thr_id];
    thr->id = stratum_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        return 1;

    /* start stratum thread */
    err = thread_create(thr, stratum_thread);
    if (err) {
        applog(LOG_ERR, "stratum thread create failed");
        return 1;
    }

    tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));


	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++) {
		thr = &thr_info[i];

		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		err = thread_create(thr, miner_thread);
		if (err) {
			applog(LOG_ERR, "thread %d create failed", i);
			return 1;
		}
	}

	applog(LOG_INFO, "%d miner threads started, "
        "using 'sha3' algorithm.", opt_n_threads);

	pthread_join(thr_info[work_thr_id].pth, NULL);

	applog(LOG_WARNING, "workio thread dead, exiting.");

	return 0;
}
