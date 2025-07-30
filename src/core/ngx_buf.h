
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

struct ngx_buf_s {
    u_char          *pos; /*指向已处理的数据的位置*/
    u_char          *last;/*指向所处理的数据的结尾位置*/
    off_t            file_pos;/*指向所处理的文件数据的开始位置*/
    off_t            file_last;/*指向所处理的文件数据的结尾位置*/

    u_char          *start;  //缓冲区开始的位置
    u_char          *end;    //缓冲区结尾的位置
    ngx_buf_tag_t    tag;   //用于标记缓冲区的属性
    ngx_file_t      *file;  //缓冲区所关联的文件
    ngx_buf_t       *shadow;


    /* the buf's content could be changed */
    unsigned         temporary:1; //缓冲区的内容可以改变

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1; //缓冲区的内容为只读，且内容不可改变

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1; //mmap映射过来的内存不可改变

    unsigned         recycled:1; //是否可回收
    unsigned         in_file:1; //是否在处理一个文件
    unsigned         flush:1;   //是否需要进行刷盘操作
    unsigned         sync:1;    //是否需要进行同步
    unsigned         last_buf:1;//是否为缓冲区链表ngx_chain_t上的最后一块待处理缓冲区
    unsigned         last_in_chain:1;//是否为缓冲区链表ngx_chain_t上的最后一块缓冲区

    unsigned         last_shadow:1;
    unsigned         temp_file:1;//表示当前缓冲区是否属于临时文件

    /* STUB */ int   num;
};

/*
将buf串联起来
*/
struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;//当前正在处理的缓冲区
    ngx_chain_t                 *in;//待处理的缓冲区链表？
    ngx_chain_t                 *free;//未使用的缓冲区链表
    ngx_chain_t                 *busy;//正在使用的缓冲区链表

    unsigned                     sendfile:1;//是否使用零拷贝
    unsigned                     directio:1;//是否启用直接IO
    unsigned                     unaligned:1;//是否支持为对齐的内存访问？
    unsigned                     need_in_memory:1;//数据是否必须保留在内存？
    unsigned                     need_in_temp:1;//数据是否需要临时储存在文件？
    unsigned                     aio:1;//是否使用异步IO

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;//内存对齐偏移量

    ngx_pool_t                  *pool;//所关联的内存池
    ngx_int_t                    allocated;//已经分配的缓冲区数量
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;//缓冲区标志

    ngx_output_chain_filter_pt   output_filter;//缓冲区过滤器
    void                        *filter_ctx;//传给过滤器的上下文
};


typedef struct {
    ngx_chain_t                 *out;//输出的缓冲区链
    ngx_chain_t                **last;//输出缓冲区链表最后一个元素
    ngx_connection_t            *connection;//网络连接
    ngx_pool_t                  *pool;//关联的内存池
    off_t                        limit;//单次写入操作的最大数量限制
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)       ((b)->temporary || (b)->memory || (b)->mmap)
#define ngx_buf_in_memory_only(b)  (ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_special(b)                                                   \
    (((b)->flush || (b)->last_buf || (b)->sync)                              \
     && !ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_sync_only(b)                                                 \
    ((b)->sync && !ngx_buf_in_memory(b)                                      \
     && !(b)->in_file && !(b)->flush && !(b)->last_buf)

/*未处理数据的大小*/
#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) ((b)->last - (b)->pos):                  \
                            ((b)->file_last - (b)->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);

//将chain节点归还到内存池中
#define ngx_free_chain(pool, cl)                                             \
    (cl)->next = (pool)->chain;                                              \
    (pool)->chain = (cl)



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
