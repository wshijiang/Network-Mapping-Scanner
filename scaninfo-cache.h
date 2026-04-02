//#pragma once

#ifndef SCANINFO_CACHE_H


#include <stdlib.h>
#include <stdio.h>
#include "postgresql/libpq-fe.h"
#include "common-types.h"
#include "config.h"



CacheManager* create_cache_manager(void);
IPEntry* create_ip_entry(const char*, unsigned, const char*);
int expend_info_arry(IPEntry*);
int add_data_to_entry(IPEntry*, \
    unsigned short, const char*, const char*, const char*);
/*
* 将数据添加到缓存中
*/
int add_scan_result_to_cache(CacheManager *manager, const char *ip, const char *scanner_name, \
    unsigned port, const char *service, const char *protocol, const char *banner);

int write_to_database(const PGconn*, const CacheManager*);
int clear_cache_data(CacheManager*);
int clear_cache_manager(CacheManager*);
//unsigned get_cache_status(CacheManager*);

#endif // !SCANINFO_CACHE_H