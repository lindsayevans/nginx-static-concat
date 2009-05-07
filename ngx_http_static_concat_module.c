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


static char* ngx_http_static_concat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_static_concat_preconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_static_concat_postconf(ngx_conf_t *cf);

static void* ngx_http_static_concat_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_static_concat_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

typedef struct {
    ngx_flag_t  enable;
} ngx_http_static_concat_loc_conf_t;

static ngx_command_t  ngx_http_static_concat_commands[] = {
    { ngx_string("static_concat"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_static_concat,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_static_concat_module_ctx = {
    NULL,			    /* preconfiguration */
    NULL,			    /* postconfiguration */

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
    size_t root;
    ngx_str_t path;
    u_char *requested_path;
    ngx_open_file_info_t of;

    ngx_buf_t    *b;
    ngx_chain_t   out;


    ngx_http_static_concat_loc_conf_t  *cglcf;
    cglcf = ngx_http_get_module_loc_conf(r, ngx_http_static_concat_module);

    ngx_http_core_loc_conf_t  *clcf;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if(cglcf->enable){
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Concat enabled");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Requested URI: %V", &r->uri);
	

// if file not found, has +
//  loop over requested files
//   if one doesnt exist, break out & return???
//   add name (plus .js if not there) to files array
//  loop over files array
//   concat to new file (name = requested file)


	// Check if URI contains + char
	if(ngx_strchr(r->uri.data, '+') == NULL){
	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Plus char not found in URI, returning");
	    return NGX_DECLINED;
	}

	// Remove / from front of requested URI
	requested_path = (u_char *) malloc(ngx_strlen(r->uri.data)*sizeof(ngx_str_t));
	size_t len = (size_t) r->uri.len;
	size_t i;
	for(i = 1; i < len; i++){
	    requested_path[i-1] = r->uri.data[i];
	}

	// Check for invalid characters in requested path
	// TODO: any escaped chars?
	if(ngx_strchr(requested_path, '/')){
	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Invalid char found in requested path: %s at: %i", requested_path, ngx_strchr(requested_path, '/'));
	    return NGX_DECLINED;
	}
	free(requested_path);

	// Check if file exists etc.
	// TODO: probably more efficient to use stat() or access() here
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

	// Split requested URI into component file names & attach '.js' if needed
	u_int max_files = 10; // max files to concat, TODO: make config var or something
	u_char *files[max_files];
	u_int ii = 0, jj = 0;
	files[ii] = (u_char *) malloc(ngx_strlen(r->uri.data)*sizeof(u_char *));
	for(i = 1; i < r->uri.len + 1; i++){
	    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "URI char: %i : %c", i, r->uri.data[i]);
	    if(i == r->uri.len || r->uri.data[i] == '+'){

		// Append ".js" if not there
		// TODO: this is JSCDN specific, need to make a config var or something - work out from last three chars of URI?
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

	// Loop over requested files & add to cat command
	// TODO: this is a potential security problem - need to either make absolutely sure requested files are 
	// sanitised or concat in code
	ngx_str_t cmd;
	cmd.data = ngx_pcalloc(r->pool, (3 + (1 + ngx_strlen(&clcf->root)) * ii + 3 + ngx_strlen(&r->uri)));
	cmd.len = ngx_sprintf(cmd.data, "cat") - cmd.data;

	for(i = 0; i < ii; i++){
	    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing file: %i %V/%s", i, &clcf->root, (char *) files[i]);
	    // TODO: skip file if not exist
	    cmd.len = ngx_sprintf(cmd.data, "%s %V/%s", cmd.data, &clcf->root, files[i]) - cmd.data;
	}
	cmd.len = ngx_sprintf(cmd.data, "%s > %s", cmd.data, path.data) - cmd.data;

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Command: %s", cmd.data);

	int ret;
/* 
 * Getting these errors - guessing they're permission based:
 * shell-init: error retrieving current directory: getcwd: cannot access parent directories: Permission denied
 * job-working-directory: error retrieving current directory: getcwd: cannot access parent directories: Permission denied
*/
	ret = system((char *) cmd.data);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Command returned: %i", ret);

	free(files[ii]);

	// TODO: write path.data to concat log - log file should be a config var
	// TODO: write headers file (use macros so only if static headers module included)

	// Subrequest for cncatted file
	// TODO: will this be a different URI if we skip non-existent? (bad idea, I think)
	return ngx_http_subrequest(r, &r->uri, NULL /* args */, NULL /* callback */, NULL, 0 /* flags */);

    }

    return ngx_http_output_filter(r, &out); // Do we ever get here?

}

static char *
ngx_http_static_concat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_static_concat_loc_conf_t *cglcf = conf;


    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_static_concat_handler;

    // TODO: disable if 'off'
    // see gzip module for example
    cglcf->enable = 1;

    return NGX_CONF_OK;
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
    return conf;
}

static char *
ngx_http_static_concat_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_static_concat_loc_conf_t *prev = parent;
    ngx_http_static_concat_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}

