/*
 *  Copyright 2009 Lindsay Evans <http://linz.id.au/> 
 *
 *  The following is released under the Creative Commons BSD license,
 *  available for your perusal at `http://creativecommons.org/licenses/BSD/`
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/stat.h>


static ngx_int_t ngx_http_static_concat_init(ngx_conf_t *cf);
static void* ngx_http_static_concat_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_static_concat_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

typedef struct {
    ngx_flag_t	enable;
    ngx_str_t	log_path;
} ngx_http_static_concat_loc_conf_t;

static ngx_command_t  ngx_http_static_concat_commands[] = {
    { ngx_string("static_concat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_static_concat_loc_conf_t, enable),
      NULL },
    { ngx_string("static_concat_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_static_concat_loc_conf_t, log_path),
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_static_concat_module_ctx = {
    NULL,			    /* preconfiguration */
    ngx_http_static_concat_init,    /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_static_concat_create_loc_conf,  /* create location configuration */
    ngx_http_static_concat_merge_loc_conf /* merge location configuration */
};


ngx_module_t  ngx_http_static_concat_module = {
    NGX_MODULE_V1,
    &ngx_http_static_concat_module_ctx, /* module context */
    ngx_http_static_concat_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_static_concat_handler(ngx_http_request_t *r)
{
    size_t		    root;
    ngx_str_t		    path;
    u_char		    *requested_path;
    ngx_open_file_info_t    of;

    ngx_http_static_concat_loc_conf_t	*cglcf;
    ngx_http_core_loc_conf_t		*clcf;
    cglcf = ngx_http_get_module_loc_conf(r, ngx_http_static_concat_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if(cglcf->enable){
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Concat enabled");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Requested URI: %V", &r->uri);
	
	/* Check if URI contains + char */
	if(ngx_strchr(r->uri.data, '+') == NULL){
	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Plus char not found in URI, returning");
	    return NGX_DECLINED;
	}

	/* Remove / from front of requested URI */
	requested_path = (u_char *) malloc(ngx_strlen(r->uri.data)*sizeof(ngx_str_t));
	size_t len = (size_t) r->uri.len;
	size_t i;
	for(i = 1; i < len; i++){
	    requested_path[i-1] = r->uri.data[i];
	}
	requested_path[i] = '\0';

	/* Check for invalid characters in requested path */
/*
	ngx_int_t n;
	ngx_regex_t *invalid_chars_regex;
	ngx_str_t invalid_chars_pattern;
	ngx_str_t err;
	u_char errstr[NGX_MAX_CONF_ERRSTR];
	err.len = NGX_MAX_CONF_ERRSTR;
	err.data = errstr;

	// TODO: make regex a config var
	// Basic: "[^\\.+\\-a-z0-9]+"
	// Include '..': "\\.\\.|[^\\.+\\-a-z0-9]+"
	invalid_chars_pattern.data = ngx_pcalloc(r->pool, 100); // TODO: use proper size
	invalid_chars_pattern.len = ngx_sprintf(invalid_chars_pattern.data, "X") - invalid_chars_pattern.data;
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "invalid_chars_pattern: %V", &invalid_chars_pattern);
	
	invalid_chars_regex = ngx_regex_compile(&invalid_chars_pattern, NGX_REGEX_CASELESS, r->pool, &err);
	if(invalid_chars_regex == NULL){
	    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "invalid_chars_regex is NULL: %V", &err);
//invalid_chars_regex is NULL: pcre_compile() failed: internal error: code overflow in "jsERCP3" at "",PI?Rt ...
// caused by ngx_pcalloc() on invalid_chars_pattern.data being wrong
	}
	n = ngx_regex_exec(invalid_chars_regex, (ngx_str_t *) &requested_path, NULL, 0);
	if (n != NGX_REGEX_NO_MATCHED) {
	//if(ngx_strchr(requested_path, '/')){
	    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "Invalid char found in requested path: %s @ %i", requested_path, n);
	    return NGX_DECLINED;
	}
*/

	if(strstr((const char *) requested_path, "..") != NULL || strstr((const char *) requested_path, "/") != NULL){
	    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "Invalid char found in requested path: %s", requested_path);
	    return NGX_DECLINED;
	}


	/* Check if file exists etc. */
	// TODO: probably more efficient to use stat() or access() here - or ngx_is_file()
	ngx_http_map_uri_to_path(r, &path, &root, 0);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Requested file: %s", path.data);

	of.test_dir = 0;
	of.valid = clcf->open_file_cache_valid;
	of.min_uses = clcf->open_file_cache_min_uses;
	of.errors = clcf->open_file_cache_errors;
	of.events = clcf->open_file_cache_events;

	ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool);
        switch (of.err) {
	case ENOENT: // requested file doesn't exist, keep processing
    	    break;
    	default:
	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Requested real file: %s", path.data);
            return NGX_DECLINED;
	}
	// Hitting this for some reason
	//if (of.is_dir) {
	//    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Trying to concat dir: %s", path.data);
        //    return NGX_DECLINED;
	//}

	/* Split requested URI into component file names & attach '.js' if needed */
	// TODO (v2): advanced merging
	u_int max_files = 10; // max files to concat, TODO: make config var or something
	u_char *files[max_files];
	u_int ii = 0, jj = 0;
	files[ii] = (u_char *) malloc(ngx_strlen(r->uri.data)*sizeof(u_char *));
	for(i = 1; i < r->uri.len + 1; i++){
	    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "URI char: %i : %c", i, r->uri.data[i]);
	    if(i == r->uri.len || r->uri.data[i] == '+'){

		// Append ".js" if not there
		// TODO: this is JSCDN specific, need to make a config var or something - or work out from last three chars of URI?
		if(!(
		    files[ii][jj-3] == '.' &&
		    files[ii][jj-2] == 'j' &&
		    files[ii][jj-1] == 's'
		)){
		    files[ii][jj++] = '.';
		    files[ii][jj++] = 'j';
		    files[ii][jj++] = 's';
		}

		files[ii][jj++] = '\0';
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Added file to stack: %s", files[ii]);

		ii++;
		files[ii] = (u_char *) malloc(ngx_strlen(r->uri.data)*sizeof(u_char *));    
		jj = 0;
		if(ii > max_files){
		    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "Maximum number of %i files reached: %V", max_files, &r->uri);
		    break;
		}
		continue;
	    }
	    files[ii][jj] = r->uri.data[i];
	    jj++;
	}

	/* Loop over requested files & add to cat command */
	// TODO: this is a potential security problem - need to either make absolutely sure requested files are 
	// sanitised or concat in code
	// FIXME: subrequest is running before command has finished concatting, probably need to concat in code & output
	ngx_str_t cmd;
	cmd.data = ngx_pcalloc(r->pool, (3 + (1 + ngx_strlen(&clcf->root)) * ii + 3 + ngx_strlen(&r->uri)));
	cmd.len = ngx_sprintf(cmd.data, "cat") - cmd.data;

	for(i = 0; i < ii; i++){
	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing file: %i %V/%s", i, &clcf->root, (char *) files[i]);
	    cmd.len = ngx_sprintf(cmd.data, "%s %V/%s", cmd.data, &clcf->root, files[i]) - cmd.data;
	}
	cmd.len = ngx_sprintf(cmd.data, "%s > %s", cmd.data, path.data) - cmd.data;

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Command: %s", cmd.data);

	//int ret = -1;
	FILE *ret;
/* 
 * Getting these errors in dev - guessing they're permission based:
 * shell-init: error retrieving current directory: getcwd: cannot access parent directories: Permission denied
 * job-working-directory: error retrieving current directory: getcwd: cannot access parent directories: Permission denied
*/
	//ret = system((char *) cmd.data);
	ret = popen((char *) cmd.data, "r");
	//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Command returned: %i", ret);

	free(files[ii]);

	/* Subrequest for concatted file */
	if(ret){

	    /* Write requested path to concat log */
	    // TODO: probably should use built-in logging stuff for this
	    if(ngx_strlen(&cglcf->log_path) != 0){
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Logging concatted file: %s", requested_path);
		ngx_fd_t    fd;
		fd = ngx_open_file(&cglcf->log_path, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
		if(fd == NGX_INVALID_FILE){
		    char *lErrString	= strerror (ngx_errno);
		    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Could not open concat log for appending: %V, %i (%s)", &cglcf->log_path, ngx_errno, lErrString);
		}else{
		    ngx_write_fd(fd, requested_path, ngx_strlen(requested_path));
		    ngx_write_fd(fd, "\n", ngx_strlen("\n"));
		}
		ngx_close_file(fd);
	    }

	    free(requested_path);
	    
	    // TODO (v2): write headers file (use macros so only if static headers module included)

	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "popen() succeeded, doing the subrequest thang");
	    pclose(ret);
	    return ngx_http_subrequest(r, &r->uri, NULL /* args */, NULL /* callback */, NULL, 0 /* flags */);
	}else{
	    free(requested_path);

	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "popen() failed");
	    return NGX_DECLINED;
	}

    }

    return NGX_DECLINED;

}

static ngx_int_t
ngx_http_static_concat_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
	return NGX_ERROR;
    }
    *h = ngx_http_static_concat_handler;

    return NGX_OK;
}

static void *
ngx_http_static_concat_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_static_concat_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_static_concat_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    //conf->log_path = NGX_CONF_UNSET; // set by ngx_pcalloc()
    return conf;
}

static char *
ngx_http_static_concat_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_static_concat_loc_conf_t *prev = parent;
    ngx_http_static_concat_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->log_path, prev->log_path, "");

    return NGX_CONF_OK;
}

