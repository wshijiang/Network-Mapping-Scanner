#ifndef CONFIG_H
#define CONFIG_H

#include <string.h>
#include <time.h>
#include <stdio.h>
#include "tomlc17.h"
#include "cJSON.h"

struct config_field_t
{
	const char *key;
	toml_type_t value;
};

/*
* 日志等级，分别为 DEBUG = 1、INFO = 2、WARN = 3、ERROR = 4
*/
enum LOGLEVEL {
    LOG_LEVEL_DEBUG = 1, LOG_LEVEL_INFO, LOG_LEVEL_WARN, LOG_LEVEL_ERROR
};

/*
* 日志写入位置分别为控制台、文件、同时
*/
enum LOGTYPE {
    LOG_TYPE_CONSOLE = 1, LOG_TYPE_FILE, LOG_TYPE_ALL
};

/* 加载配置文件，并且可以选择是否热加载
 * 当成功时返回非零值，失败则返回 -1
 * 函数接受 3 个参数，分别表示存放配置文件地址的指针、配置文件名、是否热重载（值为非零时启用热重载，且只有部分参数支持热重载）
*/
int loading_config(toml_result_t *config_result, const char *filename, int hot_reloading);

/*
* 该函数用于写入日志，可以选择是否写入文件，默认输出为标准错误
* 当一切正常时返回 1，出现错误时返回 0，且在标准错误中打印相关信息
*/
int log_to(const char *level, const char *event, const char *message, const char *event_path, enum LOGTYPE type);
#endif // !CONFIG_H