
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;// 清除操作的回调函数
    void                 *data;//实际指向的内存区域
    ngx_pool_cleanup_t   *next;//指向下一个cleanup内存块
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next;//指向下一个大内存块
    void                 *alloc;//实际指向的内存块
};


typedef struct {
    u_char               *last;//指向内存池中可用内存的开始地址
    u_char               *end;//指向内存池中内存的结尾地址
    ngx_pool_t           *next;//指向下一个内存池
    ngx_uint_t            failed;//记录当前内存池分配内存失败的次数
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d; //内存池的数据区域
    size_t                max;  //d每次允许分配的最大内存大小，小于等于max的，采用d进行分配，否则采用large进行分配
    ngx_pool_t           *current; //当前所在的内存池
    ngx_chain_t          *chain;    //缓冲区列表
    ngx_pool_large_t     *large;    //分配大内存的链表
    ngx_pool_cleanup_t   *cleanup;  //可以自定义清除函数的内存块
    ngx_log_t            *log;//日志
};


typedef struct {
    ngx_fd_t              fd;   
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
