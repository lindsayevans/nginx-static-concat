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

typedef struct {
    ngx_uint_t  static_json_callback;
} ngx_http_static_json_callback_loc_conf_t;

//static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static void * ngx_http_static_json_callback_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_static_json_callback_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_static_json_callback_init(ngx_conf_t *cf);
//static ngx_int_t ngx_http_static_json_callback_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_static_json_callback_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_command_t  ngx_http_static_json_callback_commands[] = {
    { ngx_string( "static_json_callback" ),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof( ngx_http_static_json_callback_loc_conf_t, static_json_callback),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_static_json_callback_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_static_json_callback_init,             /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_static_json_callback_create_loc_conf,  /* create location configuration */
    ngx_http_static_json_callback_merge_loc_conf,   /* merge location configuration */
};

ngx_module_t  ngx_http_static_json_callback_module = {
    NGX_MODULE_V1,
    &ngx_http_static_json_callback_module_ctx,  /* module context */
    ngx_http_static_json_callback_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static void * ngx_http_static_json_callback_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_static_json_callback_loc_conf_t    *conf;

    conf = ngx_pcalloc( cf->pool, sizeof( ngx_http_static_json_callback_loc_conf_t ) );
    if ( NULL == conf ) {
        return NGX_CONF_ERROR;
    }
    conf->static_json_callback = NGX_CONF_UNSET_UINT;
    return conf;
}

static char * ngx_http_static_json_callback_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_static_json_callback_loc_conf_t *prev = parent;
    ngx_http_static_json_callback_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value( conf->static_json_callback, prev->static_json_callback, 0 );

    if ( conf->static_json_callback != 0 && conf->static_json_callback != 1 ) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
            "static_json_callback must be 'on' or 'off'");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_static_json_callback_init(ngx_conf_t *cf) {

    //ngx_http_next_header_filter = ngx_http_top_header_filter;
    //ngx_http_top_header_filter = ngx_http_static_json_callback_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_static_json_callback_body_filter;

    return NGX_OK;
}
/*
static ngx_int_t ngx_http_static_json_callback_header_filter(ngx_http_request_t *r) {

    ngx_http_static_json_callback_loc_conf_t   *loc_conf;
    ngx_str_t args;
    int content_length;

    loc_conf = ngx_http_get_module_loc_conf( r, ngx_http_static_json_callback_module );
    if(loc_conf->static_json_callback == 1){
	args = r->args;
	content_length = (int) r->headers_out.content_length;

	r->headers_out.content_type.len = content_length;
	
	//ngx_http_clear_content_length(r);

    }

    return ngx_http_next_header_filter(r);
}
*/
static ngx_int_t ngx_http_static_json_callback_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {


    ngx_chain_t *chain_link;
    int chain_contains_last_buffer = 0;

    for ( chain_link = in; chain_link != NULL; chain_link = chain_link->next ) {

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "buf->pos: %s", chain_link->buf->pos);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "buf->last_buf: %i", chain_link->buf->last_buf);

        if (chain_link->buf->last_buf)
            chain_contains_last_buffer = 1;
    }
    if (!chain_contains_last_buffer)
        return ngx_http_next_body_filter(r, in);


    ngx_buf_t    *b;
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error allocating memory for buffer");
        return NGX_ERROR;
    }
    b->pos = (u_char *) "Served by Nginx";
    b->last = b->pos + sizeof("Served by Nginx") - 1;

    ngx_chain_t   added_link;
/*
    added_link = ngx_alloc_chain_link(r->pool);
    if(added_link == NULL){
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error allocating memory for buffer chain link");
	return NGX_ERROR;
    }

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Memory allocated");

*/
    added_link.buf = b;
	//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "added buffer: %s", added_link->buf->pos);

    added_link.next = NULL;
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "2");

    chain_link->next = (ngx_chain_t  *) added_link; // worker process 59554 exited on signal 10

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "3");

    chain_link->buf->last_buf = 0;
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "4");
    added_link->buf->last_buf = 1;
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Next link created & assigned");

    return ngx_http_next_body_filter(r, in);


/*
    ngx_chain_t *chain_link, *added_link;
    int chain_contains_last_buffer = 0;

    for ( chain_link = in; chain_link != NULL; chain_link = chain_link->next ) {
        if (chain_link->buf->last_buf)
            chain_contains_last_buffer = 1;
    }
    if (!chain_contains_last_buffer){
        return ngx_http_next_body_filter(r, in);
    }
    ngx_buf_t    *b;
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->pos = (u_char *) "X";
    b->last = b->pos + sizeof("X") - 1;

    added_link = ngx_alloc_chain_link(r->pool);
    if(added_link == NULL){
	return NGX_ERROR;
    }

    added_link->buf = b;
    added_link->next = NULL;
    chain_link->next = added_link;
    chain_link->buf->last_buf = 0;
    added_link->buf->last_buf = 1;
    return ngx_http_next_body_filter(r, added_link);
*/
}

