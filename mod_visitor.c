#include "apr.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

module AP_MODULE_DECLARE_DATA visitor_module;

typedef struct {
	int enabled;
	char *domain;
	apr_int64_t vexpiry;
	apr_int64_t sexpiry;
} visitor_dir_rec;

static uint8_t visitor_image[] = {
	// GIF header
	0x47, 0x49, 0x46,
	// version (89a)
	0x38, 0x39, 0x61,
	// image size (1x1 px)
	0x01, 0x00, 0x01, 0x00,
	// flags + color index
	0x90, 0x00, 0x00,
	// color palette
	0xff, 0xff, 0xff,
	// image block
	0x00, 0x00, 0x00,
	0x2c, 0x00, 0x00,
	0x00, 0x00, 0x01,
	0x00, 0x01, 0x00,
	0x00, 0x02, 0x02,
	0x04, 0x01, 0x00,
	// trailer
	0x3b
};

static
void set_cookie(request_rec *r,
		const char *name, const char *val,
		apr_time_t expiry)
{
	/* calculate expiry time in GMT */
	apr_time_exp_t tms;
	apr_time_exp_gmt(&tms,
			r->request_time + apr_time_from_sec(expiry));

	/* generate cookie header */
	char *new_cookie;
	new_cookie = apr_psprintf(r->pool,
			"%s=%s; path=/",
			name, val);

	if (expiry > 0) {
		new_cookie = apr_psprintf(r->pool,
				"%s; expires=%s, "
				"%.2d-%s-%.2d %.2d:%.2d:%.2d GMT",
				new_cookie, apr_day_snames[tms.tm_wday],
				tms.tm_mday, apr_month_snames[tms.tm_mon],
				tms.tm_year % 100,
				tms.tm_hour, tms.tm_min, tms.tm_sec);
	}

	/* append domain name if configured */
	visitor_dir_rec *dcfg = ap_get_module_config(r->per_dir_config, &visitor_module);

	if (dcfg->domain != NULL) {
		new_cookie = apr_pstrcat(r->pool,
				new_cookie, "; domain=",
				dcfg->domain, NULL);
	}

	/* add cookie header */
	apr_table_addn(r->headers_out, "Set-Cookie", new_cookie);
}

static
const char *get_cookie(request_rec *r, const char *name)
{
	const char *cookies;
	cookies = apr_table_get(r->headers_in, "Cookie");

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"searching cookie '%s' in '%s'", name, cookies);

	if (cookies == NULL)
		return NULL;

	const char *re_str = apr_pstrcat(r->pool,
			"^", name, "=([^;,]+)|[;,][ \t]*", name, "=([^;,]+)", NULL);

	ap_regex_t *re_bin = ap_pregcomp(r->pool, re_str, AP_REG_EXTENDED);
	ap_assert(re_bin != NULL);

	char *val = NULL;
	ap_regmatch_t regm[3];

	if (!ap_regexec(re_bin, cookies, 3, regm, 0)) {
		if (regm[1].rm_so != -1)
			val = apr_pstrndup(r->pool,
					cookies + regm[1].rm_so,
					regm[1].rm_eo - regm[1].rm_so);
		if (regm[2].rm_so != -1)
			val = apr_pstrndup(r->pool,
					cookies + regm[2].rm_so,
					regm[2].rm_eo - regm[2].rm_so);
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"found cookie: '%s'", val);

	return val;
}

static
const char *make_cookie(request_rec *r, const char *name, apr_time_t expiry)
{
	const char *id;

	if ((id = apr_table_get(r->subprocess_env, "UNIQUE_ID")))
		set_cookie(r, name, id, expiry);

	return id;
}

static
void spot_cookies(request_rec *r)
{
	visitor_dir_rec *dcfg = ap_get_module_config(r->per_dir_config,
			&visitor_module);

	/* do not run in subrequests */
	if (r->main)
		return;

	const char *a = get_cookie(r, "__vta");
	const char *b = get_cookie(r, "__vtb");
	const char *c = get_cookie(r, "__vtc");

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"got visitor cookies: a=%s; b=%s; c=%s", a, b, c);

	if (a == NULL) {
		a = make_cookie(r, "__vta", dcfg->vexpiry);
		b = make_cookie(r, "__vtb", dcfg->sexpiry);
		c = make_cookie(r, "__vtc", 0);
	} else if (b == NULL || c == NULL) {
		b = make_cookie(r, "__vtb", dcfg->sexpiry);
		c = make_cookie(r, "__vtc", 0);
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"new visitor cookies: a=%s; b=%s; c=%s", a, b, c);

	if (a && b)
		apr_table_setn(r->notes, "visitor-cookie",
				apr_pstrcat(r->pool, a, ";", b, NULL));

	return;
}

static
int visitor_cookie_handler(request_rec *r)
{
	if (strcmp(r->handler, "visitor-cookie"))
		return DECLINED;

	r->allowed |= (AP_METHOD_BIT << M_GET);
	if (r->method_number != M_GET)
		return DECLINED;

	/* check and set cookies */
	spot_cookies(r);

	/* send images */
	ap_set_content_type(r, "image/gif");
	ap_set_content_length(r, sizeof(visitor_image));
	ap_rwrite(visitor_image, sizeof(visitor_image), r);

	return OK;
}

static void *visitor_create_dir_config(apr_pool_t *p, char *d)
{
	visitor_dir_rec *dcfg = apr_pcalloc(p, sizeof(visitor_dir_rec));

	dcfg->enabled = 0;
	dcfg->domain  = NULL;
	dcfg->vexpiry = 2*365*24*60*60; /* aprox. 2 years */
	dcfg->sexpiry = 30*60; /* 30 minutes */

	return dcfg;
}

static const char *cmd_visitor_tracking(cmd_parms *cmd, void *mconfig, int arg)
{
	visitor_dir_rec *dcfg = mconfig;
	dcfg->enabled = arg;
	return NULL;
}

static
const char *cmd_visitor_domain(cmd_parms *cmd, void *mconfig, const char *name)
{
	visitor_dir_rec *dcfg = mconfig;

	if (strlen(name) == 0)
		return "VisitorDomain values may not be null";
	if (name[0] != '.')
		return "VisitorDomain values must begin with a dot";
	if (ap_strchr_c(&name[1], '.') == NULL)
		return "VisitorDomain values must contain at least one embedded dot";

	dcfg->domain = apr_pstrdup(cmd->pool, name);
	return NULL;
}

static
const char *cmd_visitor_expiry(cmd_parms *cmd, void *mconfig, const char *seconds)
{
	visitor_dir_rec *dcfg = mconfig;

	if (strlen(seconds) == 0)
		return "VisitorExpiry values may not be null";

	char *end;
	apr_int64_t expiry = apr_strtoi64(seconds, &end, 10);

	if (end - seconds < strlen(seconds) || expiry < 0)
		return "VisitorExpiry value is not a positive number";

	dcfg->vexpiry = expiry;
	return NULL;
}

static
const char *cmd_session_expiry(cmd_parms *cmd, void *mconfig, const char *seconds)
{
	visitor_dir_rec *dcfg = mconfig;

	if (strlen(seconds) == 0)
		return "SessionExpiry values may not be null";

	char *end;
	apr_int64_t expiry = apr_strtoi64(seconds, &end, 10);

	if (end - seconds < strlen(seconds) || expiry < 0)
		return "SessionExpiry value is not a positive number";

	dcfg->sexpiry = expiry;
	return NULL;
}

static
const command_rec visitor_cmds[] = {
	AP_INIT_FLAG(
			"VisitorTracking",
			cmd_visitor_tracking,
			NULL,
			OR_FILEINFO,
			"whether or not to enable visitor tracking"),
	AP_INIT_TAKE1(
			"VisitorDomain",
			cmd_visitor_domain,
			NULL,
			OR_FILEINFO,
			"domain to which mod_visitor cookies apply"),
	AP_INIT_TAKE1(
			"VisitorExpiry",
			cmd_visitor_expiry,
			NULL,
			OR_FILEINFO,
			"time after which visitor cookie expires in seconds"),
	AP_INIT_TAKE1(
			"SessionExpiry",
			cmd_session_expiry,
			NULL,
			OR_FILEINFO,
			"time after which session cookie expires in seconds"),
	{ NULL }
};

static
void visitor_register_hooks(apr_pool_t *p)
{
	ap_hook_handler(visitor_cookie_handler, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA visitor_module = {
	STANDARD20_MODULE_STUFF,
	visitor_create_dir_config,    /* per-directory config creater */
	NULL,                         /* dir config merger */
	NULL,                         /* server config creator */
	NULL,                         /* server config merger */
	visitor_cmds,                 /* command table */
	visitor_register_hooks        /* set up other request processing hooks */
};
