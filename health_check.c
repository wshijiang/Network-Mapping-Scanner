#include "health_check.h"
#include "http_conn.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>

/*
* 该函数主要用于测试目标获取是否正常
* 函数接收多个参数，其中 test_url 为获取目标的 url
* 函数返回一个 int 值，当一切正常时返回1，否则返回0
*/
int get_target_test(const char *test_url)
{
	cJSON *root = NULL;
	cJSON *target_ip = NULL;
	cJSON *target_port = NULL;
	cJSON *scanner_rate = NULL;


	char *result = http_requests(test_url);
	if (!result) {
		free(result);
		return 0;
	}
	root = cJSON_Parse(result);
	
	if (check_target(root, &target_ip, &target_port, &scanner_rate, 1)) {
		printf("Received: %s:%s\tRATE:%d\n", target_ip->valuestring, target_port->valuestring, scanner_rate->valueint);
		printf("\033[32m获取目标正常\n\033[0m");
	} else {
		fprintf(stderr, "\033[31m目标检查错误\n\033[0m");
	}


	free(result);
	cJSON_Delete(root);
	return 1;
}

/*
* 该函数用于检查获取到的目标数据
* 返回 int 类型，0 代表发生了错误，1 为一切正确，并且会把获取到的数据写入传入指针所指向的内存中
* 接收 2 个参数，分别为：json 根和模式（当 mode 为 0 时代表扫描中的检查，为 1 时代表处于健康检查模式）
*/
int check_target(const cJSON *root, const cJSON **ip, const cJSON **port, const cJSON **rate,const int mode)
{
	if (mode) printf("开始检查目标\n");
	if (root == NULL) {
		char *error_ptr = cJSON_GetErrorPtr();
		fprintf(stderr, "错误来自: %s\n", error_ptr);

		return 0;
	}

	/* 从整个 json 对象中提取键所对应的值 */
	*ip = cJSON_GetObjectItemCaseSensitive(root, "ip");
	*port = cJSON_GetObjectItemCaseSensitive(root, "port");
	*rate = cJSON_GetObjectItemCaseSensitive(root, "rate");

	if (!cJSON_IsString(*ip) || ((*ip)->valuestring == NULL)) {
		fprintf(stderr, "\033[31mIP 字段出现错误\n\033[0m");

		return 0;
	}

	if (!cJSON_IsString(*port) || ((*port)->valuestring == NULL)) {
		fprintf(stderr, "\033[31mPORT 字段出现错误\n\033[0m");

		return 0;
	}

	if (!cJSON_IsNumber(*rate)) {
		fprintf(stderr, "\033[31mRATE 字段出现错误\033[0m");

		return 0;
	}
	else if ((*rate)->valueint <= 0 || (*rate)->valueint > 1000000) {
		fprintf(stderr, "\033[31mRATE 字段数值异常：\n\tRATE=%d （0 < RATE <= 1000000）\033[0m", (*rate)->valueint);

		return 0;
	}

	return 1;
}