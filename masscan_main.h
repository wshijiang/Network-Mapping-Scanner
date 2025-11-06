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

typedef struct ScanData
{
    char line_data[MAX_LINE_SIZE];
    char ip[MAX_IP_SIZE];
    char protocol[MAX_PROTOCOL_SIZE];
    char service[MAX_SERVICE_SIZE];
    char banner[MAX_BANNER_SIZE];

    unsigned port;
} ScanData;

//typedef struct ScanConfig
//{
//    char* scanner_path; // masscan可执行文件路径
//    char* banner_scan_ip;
//	char* target_ip; // 扫描目标IP
//    char* target_port;
//    char* rate;      // 扫描速率
//} ScanConfig;



int scan(PGconn*, ScanData*, CacheManager*);
int scan_output_format(PGconn*, FILE*, ScanData*, CacheManager*, const char*);
//int check_scan_config(ScanConfig*);
//int free_scan_config(ScanConfig*);
//int check_write(const CacheManager*);