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


	char *result = http_requests(test_url);
	root = cJSON_Parse(result);
	
	if (root == NULL) {
		char *error_ptr = cJSON_GetErrorPtr();
		fprintf(stderr, "错误来自: %s\n", error_ptr);
		
		free(result);
		cJSON_Delete(root);
		return 0;
	}

	/* 从整个 json 对象中提取键 ip 所对应的值 */
	target_ip = cJSON_GetObjectItemCaseSensitive(root, "ip");
	target_port = cJSON_GetObjectItemCaseSensitive(root, "port");

	if (!cJSON_IsString(target_ip) || (target_ip->valuestring == NULL)) {
		fprintf(stderr, "target_ip 字段出现错误\n");
		free(result);
		cJSON_Delete(root);
		return 0;
	}

	if (!cJSON_IsString(target_port) || (target_port->valuestring == NULL)) {
		fprintf(stderr, "target_port 字段出现错误\n");
		free(result);
		cJSON_Delete(root);
		return 0;
	}

	printf("Received: %s:%s\n", target_ip->valuestring, target_port->valuestring);
	printf("获取目标正常\n");

	free(result);
	cJSON_Delete(root);
	return 1;
}