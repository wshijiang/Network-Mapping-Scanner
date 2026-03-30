#pragma once

#include "scaninfo-cache.h"

/*ipv4地址最大空间*/
#define MAX_IPV4_SIZE 16
#define MAX_IP_SIZE 40
/*协议最大空间*/
#define MAX_PROTOCOL_SIZE 10
/*banner 最大空间*/
#define MAX_BANNER_SIZE 1024 * 7
/*服务占用空间*/
#define MAX_SERVICE_SIZE 128
/*masscan 输出一行的最大空间*/
#define MAX_LINE_SIZE (MAX_IP_SIZE + MAX_PROTOCOL_SIZE + MAX_BANNER_SIZE)

struct ScanData {
    char line_data[MAX_LINE_SIZE];
    char ip[MAX_IP_SIZE];
    char protocol[MAX_PROTOCOL_SIZE];
    char service[MAX_SERVICE_SIZE];
    char banner[MAX_BANNER_SIZE];

    unsigned port;
};

/*
* 该结构体表示扫描器配置文件
*/
struct ScannerConfig {
    char *target_ip;                /* 扫描目标 IP */
    char *target_port;              /* 扫描目标 PORT */
    int source_port;                /* 执行 Masscan banner 扫描时的源端口 */
    int rate;                       /* 扫描器的包速率（使用 Masscan 扫描端口时生效） */
};



int scan(PGconn *conn, struct ScanData *ScanData, CacheManager *manager);
int scan_output_format_fd(PGconn *conn, int fd, struct ScanData *data, CacheManager *manager, const char *scanner_name);
//int check_scan_config(ScanConfig*);
//int free_scan_config(ScanConfig*);
//int check_write(const CacheManager*);