
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
    创建一个数组，主要包括两个步骤：
    （1）为管理数组的结构体进行内存分配
    （2）结构初始化，申请实际储存元素的内存
*/
ngx_array_t * ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}

/*
    清除数组，主要包括两个步骤：
    （1）如果数组中元素所占的内存尾地址等于内存池可用内存地址，那么将可用地址减去数组元素所占的内存大小
    （2）如果数组中数组结构体的尾地址等于内存池可用内存地址，那么将可用地址减去数据结构体所占内存大小

    补充：也就说如果满足不了以上条件，实际上这段内存是没有归还给内存池的
*/
void ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;

    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }

    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}

/*
    在数组中插入一个元素，返回新插入元素的内存首地址，不会实际插入要放入的数据，主要分两种情况：
    （1）如果数组当前储存的元素个数小于数组最大储存元素个数，那么直接返回内存地址，并将元素个数++
    （2）如果数组元素个数达到最大，那么考虑两种情况，如果数组所关联的内存池的可用地址等于数组的尾地址
        那么直接调整内存池的可用内存指针，分配一个元素大小，否则从内存池中分配新的内存，内存大小为原来
        的两倍，并将元素拷贝过去，但是原本的内存不会归还给相应的内存池
*/
void * ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;

        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size;
            a->nalloc++;

        } else {
            /* allocate a new array */

            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}

/*
    类似与ngx_array_push
*/
void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
