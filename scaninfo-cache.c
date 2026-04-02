//FIXME:更改注释，初步为 Doxygen
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "scaninfo-cache.h"
#include "db-postgresql.h"


/* 初始化缓存管理器 */
CacheManager *create_cache_manager()
{
    CacheManager *manager = malloc(sizeof(CacheManager));
    if (!manager) return NULL;

    manager->ip_table = NULL;
    manager->total_records = 0;
    return manager;
}


/*
 * 创建所需 IP 条目
 * @initial_capacity 默认 Info 数组容量
 */
IPEntry *create_ip_entry(const char *ip, unsigned initial_capacity, const char *scanner_name)
{
    IPEntry *entry = malloc(sizeof(IPEntry));
    if (!entry) return NULL;

    entry->ip = strdup(ip);
    if (!entry->ip)
    {
        free(entry);
        return NULL;
    }

    entry->infos = malloc(initial_capacity * sizeof(struct Info));
    if (!entry->infos)
    {
        free(entry->ip);
        free(entry);
        return NULL;
    }

    entry->scanner_name = strdup(scanner_name);
    if (!entry->scanner_name)
    {
        free(entry->infos);
        free(entry->ip);
        free(entry);
        return NULL;
    }

    entry->info_capacity = initial_capacity;
    entry->info_count = 0;
    return entry;
}


/*
 * 扩展 infos 数组
 */
int expend_info_arry(IPEntry *entry)
{
    unsigned new_capacity = entry->info_capacity * 2;

    struct Info *new_infos = realloc(entry->infos, new_capacity * sizeof(struct Info));
    if (!new_infos) return 0;

    entry->infos = new_infos;
    entry->info_capacity = new_capacity;
    return 1;
}


/*
 * 向 Info 中追加或填充一条 Service_i 记录
 *
 * 规则：
 *   - service != NULL 时，先查找 services[] 中是否存在 s==NULL 的占位记录
 *     （由 Discovered 行写入），有则原地填充，避免重复追加
 *   - 无占位或 service==NULL 时，正常追加一条新记录
 *   - service / banner 均允许为 NULL（Discovered 行仅有端口，无服务识别）
 */
static int add_service_to_info(struct Info *info,
    const char *service, const char *banner)
{
    /* 首次分配 services 数组 */
    if (!info->services)
    {
        info->services = malloc(2 * sizeof(struct Service_i));
        if (!info->services) return 0;
        info->service_capacity = 2;
        info->service_count = 0;
    }

    /* Banner 到来（service != NULL）：查找并填充空占位记录 */
    if (service)
    {
        for (unsigned i = 0; i < info->service_count; i++)
        {
            if (info->services[i].s == NULL)
            {
                info->services[i].s = strdup(service);
                if (!info->services[i].s) return 0;

                if (banner && !info->services[i].b)
                {
                    info->services[i].b = strdup(banner);
                    if (!info->services[i].b)
                    {
                        free(info->services[i].s);
                        info->services[i].s = NULL;
                        return 0;
                    }
                }
                return 1; /* 填充完毕，直接返回 */
            }
        }
    }

    /* 无空占位，或本次为 NULL/NULL（Discovered）—— 追加新记录 */
    if (info->service_count >= info->service_capacity)
    {
        unsigned new_cap = info->service_capacity * 2;
        struct Service_i *tmp = realloc(info->services,
            new_cap * sizeof(struct Service_i));
        if (!tmp) return 0;
        info->services = tmp;
        info->service_capacity = new_cap;
    }

    struct Service_i *svc = &info->services[info->service_count];
    svc->s = service ? strdup(service) : NULL;
    svc->b = banner ? strdup(banner) : NULL;

    if ((service && !svc->s) || (banner && !svc->b))
    {
        free(svc->s);
        free(svc->b);
        return 0;
    }

    info->service_count++;
    return 1;
}


/*
 * 将端口数据添加到 IPEntry 中
 *
 * - 若该 port + protocol 已存在：
 *     - service/banner 均为 NULL（重复 Discovered）→ 跳过，不写重复占位
 *     - 否则调用 add_service_to_info 追加或填充服务记录
 * - 若不存在：新建 Info 槽位，写入第一条 Service_i
 */
int add_data_to_entry(IPEntry *entry,
    unsigned short port, const char *service,
    const char *protocol, const char *banner)
{
    /* 查找相同端口 + 协议的已有 Info */
    for (unsigned i = 0; i < entry->info_count; i++)
    {
        struct Info *existing = &entry->infos[i];
        if (existing->port == (unsigned)port &&
            strcmp(existing->protocol, protocol) == 0)
        {
            /* 重复 Discovered（全 NULL）：跳过，不重复写占位 */
            if (!service && !banner) return 1;
            return add_service_to_info(existing, service, banner);
        }
    }

    /* 未找到 —— 新建 Info 槽位 */
    if (entry->info_count >= entry->info_capacity)
    {
        if (!expend_info_arry(entry)) return 0;
    }

    struct Info *info = &entry->infos[entry->info_count];
    info->port = port;
    info->services = NULL;
    info->service_count = 0;
    info->service_capacity = 0;

    info->protocol = strdup(protocol);
    if (!info->protocol) return 0;

    /*
     * service/banner 均为 NULL 时也写入一条空 Service_i，
     * 记录"端口开放但未识别服务"，等待后续 Banner 行填充
     */
    if (!add_service_to_info(info, service, banner))
    {
        free(info->protocol);
        return 0;
    }

    entry->info_count++;
    return 1;
}


/*
 * 将扫描结果添加到缓存
 */
int add_scan_result_to_cache(CacheManager *manager, const char *ip, const char *scanner_name,
    unsigned port, const char *service, const char *protocol, const char *banner)
{
    IPEntry *entry;
    HASH_FIND_STR(manager->ip_table, ip, entry);

    if (!entry)
    {
        entry = create_ip_entry(ip, 4, scanner_name);
        if (!entry) return 0;

        HASH_ADD_KEYPTR(hh, manager->ip_table, entry->ip, strlen(entry->ip), entry);
    }

    if (!add_data_to_entry(entry, port, service, protocol, banner)) return 0;

    manager->total_records++;
    return 1;
}


/*
 * 将缓存数据写入数据库
 */
int write_to_database(const PGconn *conn, const CacheManager *manager)
{
    if (!conn) return 0;

    printf("缓存数达到%d条，开始写入数据库\n", manager->total_records);
    if (!insert_batch_data(conn, manager))
    {
        fprintf(stderr, "数据插入数据库失败\n");
        clear_cache_data(manager);
        //NOTE:下次添加文件写入方案
        return 0;
    }
    else
    {
        clear_cache_data(manager);
    }

    return 1;
}


/*
 * 清理缓存数据（保留 manager 结构体本身）
 */
int clear_cache_data(CacheManager *manager)
{
    IPEntry *entry, *temp;

    HASH_ITER(hh, manager->ip_table, entry, temp)
    {
        HASH_DEL(manager->ip_table, entry);

        for (unsigned i = 0; i < entry->info_count; i++)
        {
            struct Info *info = &entry->infos[i];

            for (unsigned j = 0; j < info->service_count; j++)
            {
                free(info->services[j].s); /* free(NULL) 合法，无需额外判断 */
                free(info->services[j].b);
            }
            free(info->services);
            free(info->protocol);
        }
        free(entry->infos);
        free(entry->scanner_name);
        free(entry->ip);
        free(entry);
    }

    manager->total_records = 0;
    return 1;
}


/*
 * 清理缓存管理器（包括 manager 结构体本身）
 */
int clear_cache_manager(CacheManager *manager)
{
    if (!manager) return 0;

    clear_cache_data(manager);
    free(manager);
    return 1;
}