#include <stdlib.h>
#include "config.h"


/*
* 该函数用于写入日志，接受两个参数，分别为已打开文件的文件描述符和内容
* 需要调用者自己管理文件描述符的 打开/关闭
* 返回两个参数，0 为失败，1 为成功
*/
int write_log_to_file(const FILE *fp, const char *message)
{
	if (fp == NULL) return 0;

	if (fputs(message, fp) == EOF) return 0;

	if (fputs("\n", fp) == EOF) return 0;

	return 1;
}

/*
* 该函数用于检查是否需要滚动日志文件
* 返回一个 int 值，返回值为 0 时代表函数内部出现了错误，返回 1 时代表需要滚动，并且新建了一个日志文件（通常为 JSON 格式），-1 代表当前无需滚动
* 函数接受多个传参，分别为 unix 时间戳、滚动周期（单位为天、默认一天）、新建日志文件名格式
*/
int new_log_file(const time_t *now, const int roalling, const char *message)
{
	struct tm *t_local =NULL;
	FILE *fp = NULL;
	char log_file_name[7 + 11 + 9] = { 0 };

	t_local = localtime(now);

	if (t_local == NULL) {
		return 0;
	}

	if (!strftime(log_file_name, sizeof log_file_name, "./logs/%F_log.json", t_local)) return 0;


	if ((fp = fopen(&log_file_name, "a")) == NULL) {
		fprintf(stderr, "打开/创建日志文件失败。\n\tFile path: %s\n", log_file_name);
		return 0;
	}

	if (!write_log_to_file(fp, message)) {
		fprintf(stderr, "写入日志/检查滚动失败\n");
		fclose(fp);
		return 0;
	}

	fclose(fp);


	return 1;
}


/*
* 该函数用于写入日志，可以选择是否写入文件，默认输出为标准错误
* 当一切正常时返回 1，出现错误时返回 0，且在标准错误中打印相关信息
*/
int log_to(const char *level, const char *event, const char *message, const char *event_path, enum LOGTYPE type)
{
	cJSON *log_item = NULL, *i_timestamp = NULL, *i_level = NULL, *i_path = NULL;
	cJSON *i_fields = NULL, *i_event = NULL, *i_message = NULL;
	char *log_message = NULL;
	char l_time[20 + 5] = { 0 };

	log_item = cJSON_CreateObject();
	i_fields = cJSON_CreateObject();

	time_t now = time(NULL);
	strftime(l_time, sizeof l_time, "%F %T%z", localtime(&now));

	if (log_item == NULL || i_fields == NULL) {
		cJSON_Delete(log_item);
		fprintf(stderr, "%s [ERROR]-[log.c->log_to->cJSON_CreateObject]-[cJSON_CreateObject-ERROR]-\"cJSON_CreateObject 出现了错误\"\n", l_time);
		fprintf(stderr, "\033[31m日志文件写入失败\n\033[0m");
		return 0;
	}
	
	i_timestamp = cJSON_CreateNumber(now);
	i_level = cJSON_CreateString(level);
	i_path = cJSON_CreateString(event_path);
	i_event = cJSON_CreateString(event);
	i_message = cJSON_CreateString(message);

	if (
		!cJSON_AddItemToObject(log_item, "timestamp", i_timestamp) ||
		!cJSON_AddItemToObject(log_item, "level", i_level) ||
		!cJSON_AddItemToObject(log_item, "path", i_path) ||
		!cJSON_AddItemToObject(i_fields, "event", i_event) ||
		!cJSON_AddItemToObject(log_item, "message", i_message)
		) {
		cJSON_Delete(log_item);

		fprintf(stderr, "%s [ERROR]-[log.c->log_to->cJSON_AddItemToObject]-[cJSON_AddItemToObject-ERROR]-\"添加至 JSON 键值对时错误\"\n", l_time);
		fprintf(stderr, "\033[31m日志文件写入失败\n\033[0m");
		return 0;
	}

	log_message = cJSON_PrintUnformatted(log_item);

	if (log_message == NULL) {
		fprintf(stderr, "打印json结构失败\n");
		cJSON_free(log_message);
		cJSON_Delete(log_item);
		fprintf(stderr, "%s [ERROR]-[log.c->log_to->cJSON_Print]-[cJSON_Print-ERROR]-\"cJSON_Print 返回值为 NULL\"\n", l_time);
		fprintf(stderr, "\033[31m日志文件写入失败\n\033[0m");
		return 0;
	}


	switch (type) {
	case LOG_TYPE_FILE:
		if (!new_log_file(&now, 1, log_message)) {
			cJSON_free(log_message);
			cJSON_Delete(log_item);
			fprintf(stderr, "%s [ERROR]-[log.c->log_to->new_log_file]-[new_log_file-ERROR]-\"new_log_file 出现了错误\"\n", l_time);
			fprintf(stderr, "\033[31m日志文件写入失败\n\033[0m");
			return 0;
		}
		
		return NULL;
	case LOG_TYPE_CONSOLE:
		cJSON_free(log_message);
		cJSON_Delete(log_item);
		return NULL;
	case LOG_TYPE_ALL:
		cJSON_free(log_message);
		cJSON_Delete(log_item);
		return NULL;
	}
}