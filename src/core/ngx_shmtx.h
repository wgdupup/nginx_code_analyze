
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/*互斥锁的状态结构*/
typedef struct {
    ngx_atomic_t   lock;/*表示锁的状态，0为未锁定，1为锁定*/
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;/*表示等待锁的进程数*/
#endif
} ngx_shmtx_sh_t;

/*互斥锁的控制结构*/
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    ngx_atomic_t  *lock;/*指向共享内存中ngx_shmtx_sh_t结构的lock成员的指针*/
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t  *wait;/*指向共享内存中ngx_shmtx_sh_t结构的wait成员的指针*/
    ngx_uint_t     semaphore;/*标记是否使用信号量*/
    sem_t          sem;/*POSIX 信号量对象*/
#endif
#else/*文件锁*/
    ngx_fd_t       fd;/*文件描述符*/
    u_char        *name;/*锁文件的路径名*/
#endif
    ngx_uint_t     spin;/*自旋锁的重试次数*/
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
