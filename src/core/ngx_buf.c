
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
通过内存池中的内存创建一个buf，初始化相关的结构体变量
*/
ngx_buf_t * ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = ngx_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by ngx_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}

/*
    获取一个缓冲区链表的链表节点
    （1）如果内存池中存在可用的，那么直接返回
    （2）否则采用内存池重新分配内存获取新的缓冲区链表结构
*/
ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    cl = pool->chain;

    if (cl) {
        pool->chain = cl->next;
        return cl;
    }

    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}

/*
    获取一个buf链表，链表节点中的buf的内存大小为bufs->size，链表节点个数为bufs->num
    同时，该链表所管理的所有buf均在一个连续的内存区域中
*/
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;
    //分配所有buf所需要的内存
    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {
        //分配一个buf管理结构体
        b = ngx_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by ngx_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */

        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;
        //分配一个chain结构体，也就是链表节点
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}

/*
    将In链表中的buf缓冲区添加到chain链表的结尾，但是in链表中的节点并不会释放
*/
ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            *ll = NULL;
            return NGX_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return NGX_OK;
}

/*
    获取空闲buf链表的一个buf链表节点，如果空闲链表为空，那么采用内存池进行新节点分配
*/
ngx_chain_t * ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}

/*
    buf链表更新
    （1）如果out为NULL，那么就只是做busy节点到free的归还
    （2）如果不为NULL，那么将其接到busy结尾，然后做busy节点到free的归还
*/
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

    if (*out) {
        if (*busy == NULL) {
            *busy = *out;

        } else {
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }
    //由于busy和free为二级指针，所以更新完busy指向的是数据未处理好的buf节点，free是新归还的buf节点
    while (*busy) {
        cl = *busy;
        //如果busy链表的缓冲区标记与tag不相同，那么将其归还给内存池
        if (cl->buf->tag != tag) {
            *busy = cl->next;
            ngx_free_chain(p, cl);
            continue;
        }
        /*未处理数据的大小如果不为0，说明后续的缓冲区未处理数据大小也不为0，那么结束遍历*/
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }

        //将缓冲区待处理数据的标记重置
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        //将数据已经处理完的buf链表节点归还到free链表，方便后续继续使用
        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}

/*
    从输入链表开始，将多个连续的文件缓冲区合并为一个更大的操作单元，直到达到
    大小限制或者遇到不连续的缓冲区为止
    设计亮点：
    （1）通过合并多个连续的文件区域，减少系统调用次数
*/
off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    ngx_fd_t      fd;
    ngx_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        size = cl->buf->file_last - cl->buf->file_pos;

        //如果所处理的文件数据大小大于最大限制，那么其size等于最大限制，并进行内存对齐
        if (size > limit - total) {
            size = limit - total;

            aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                       & ~((off_t) ngx_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        total += size;//以及合并的文件大小
        fprev = cl->buf->file_pos + size;//记录前一个缓冲区记录的内容在文件中的位置
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;//返回可合并的链表节点的下一个节点

    return total;
}

/*
    根据sent要发送的数据大小，调整in指向的链表节点
*/
ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {
        //特殊数据不做处理
        if (ngx_buf_special(in->buf)) {
            continue;
        }
        //可发送的数据大小为0，那么就不能再发送了
        if (sent == 0) {
            break;
        }
        //获取未处理数据的大小
        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;
            //设置未处理数据大小为0，表示已经处理完所有数据
            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }
            //设置未处理数据大小为0，表示已经处理完所有数据
            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }
        //可发送数据大小不足以发送当前buf未处理数据大小，那么能发送多少就发送多少
        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
            //调整其已经处理的数据的指针
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;
            //调整其已经处理的数据的指针
        }

        break;
    }

    return in;
}
