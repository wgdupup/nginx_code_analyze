
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

/*共享内存结构体*/
struct ngx_shm_zone_s {
    void                     *data;//指向共享内存区域的用户数据
    ngx_shm_t                 shm;//共享内存描述结构体
    ngx_shm_zone_init_pt      init;//共享内存初始化时的回调函数
    void                     *tag;//标识共享内存的创建者
    void                     *sync;//指向同步对象（如互斥锁）
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
    void                  ****conf_ctx; //模块配置上下文数组，每个配置可能不一样，所以用void*
    ngx_pool_t               *pool;//内存池 

    ngx_log_t                *log;//日志
    ngx_log_t                 new_log; // 新日志对象（用于热升级）

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;//文件描述符到连接的映射
    ngx_connection_t         *free_connections;//空闲连接链表
    ngx_uint_t                free_connection_n;//空闲连接链表数量

    ngx_module_t            **modules; //模块数组
    ngx_uint_t                modules_n;//模块数量
    ngx_uint_t                modules_used; //是否使用动态模块   /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue;//可重复使用连接队列
    ngx_uint_t                reusable_connections_n;//可重复使用连接队列数量
    time_t                    connections_reuse_time;

    ngx_array_t               listening;//监听套接字数组
    ngx_array_t               paths;// 配置文件中的路径

    ngx_array_t               config_dump;
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    ngx_list_t                open_files;//打开的文件列表
    ngx_list_t                shared_memory;//共享内存列表

    ngx_uint_t                connection_n;//连接数上限
    ngx_uint_t                files_n;//文件数上限

    ngx_connection_t         *connections;//连接数组
    ngx_event_t              *read_events;//读事件数组
    ngx_event_t              *write_events;//写事件数组

    ngx_cycle_t              *old_cycle;//指向旧配置

    ngx_str_t                 conf_file;//配置文件路径
    ngx_str_t                 conf_param;//配置参数
    ngx_str_t                 conf_prefix;//配置目录前缀
    ngx_str_t                 prefix;//安装前缀
    ngx_str_t                 error_log;
    ngx_str_t                 lock_file;//锁文件路径
    ngx_str_t                 hostname;//主机名
};

/*核心模块配置结构体*/
typedef struct {
    ngx_flag_t                daemon;// 是否以守护进程模式运行
    ngx_flag_t                master; // 是否为主进程

    ngx_msec_t                timer_resolution;// 定时器
    ngx_msec_t                shutdown_timeout;// 关闭超时时间

    ngx_int_t                 worker_processes;// 工作进程数量
    ngx_int_t                 debug_points;

    ngx_int_t                 rlimit_nofile;// 最大打开文件数限制
    off_t                     rlimit_core; // 核心转储文件大小限制

    int                       priority;// 进程优先级（nice值）

    ngx_uint_t                cpu_affinity_auto;// 是否自动设置CPU亲和性
    ngx_uint_t                cpu_affinity_n;// CPU亲和性掩码数量
    ngx_cpuset_t             *cpu_affinity; // CPU亲和性掩码数组

    char                     *username; // 用户名称
    ngx_uid_t                 user;// 用户ID
    ngx_gid_t                 group;// 用户组ID

    ngx_str_t                 working_directory; // 工作目录
    ngx_str_t                 lock_file;// 锁文件路径

    ngx_str_t                 pid;// PID文件路径
    ngx_str_t                 oldpid;// 旧PID文件路径

    ngx_array_t               env;// 环境变量数组
    char                    **environment;

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
