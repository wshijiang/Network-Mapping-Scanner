
#include "http_conn.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

typedef struct MemoryStruct {
	char* memory;
	size_t size;
}MemoryStruct;

/**
* 代码来自官网 https://everything.curl.dev/examples/getinmem.html
*/
static size_t
mem_cb(void* contents, size_t size, size_t nmemb, void* userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct* mem = (struct MemoryStruct*)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		/* out of memory */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = '\0';

	return realsize;
}
/**
* 调用者需要free
*/
char* http_requests(const char* url)
{
	CURL* curl;
	CURLcode http_res;
	

	MemoryStruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;


	/*初始化libcurl*/
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();

	if (!curl)
	{
		fprintf(stderr, "curl错误\n");
		return NULL;
	}
	/**
	* 设置请求URL
	*/
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mem_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "User-Agent: Scanner/1.0");
	if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	http_res = curl_easy_perform(curl);
	if (http_res != CURLE_OK)
	{
		fprintf(stderr, "请求错误\n", curl_easy_strerror(http_res));
		free(chunk.memory);
		chunk.memory = NULL;
	}
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	curl_slist_free_all(headers);
	return chunk.memory;
}


//发送停止邮件
int send_stop_email(void)
{
	CURL* curl;
	CURLcode res = CURLE_OK;
	struct curl_httppost* formpost = NULL;
	struct curl_httppost* lastptr = NULL;

	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();

	if (curl) {
		// 构建 multipart/form-data 
		curl_formadd(&formpost, &lastptr,
			CURLFORM_COPYNAME, "from",
			CURLFORM_COPYCONTENTS, "Excited User <postmaster@YOUR_DOMAIN_NAME>",
			CURLFORM_END);

		curl_formadd(&formpost, &lastptr,
			CURLFORM_COPYNAME, "to",
			CURLFORM_COPYCONTENTS, "recipient-1@example.com",
			CURLFORM_END);

		curl_formadd(&formpost, &lastptr,
			CURLFORM_COPYNAME, "to",
			CURLFORM_COPYCONTENTS, "recipient-2@example.com",
			CURLFORM_END);

		curl_formadd(&formpost, &lastptr,
			CURLFORM_COPYNAME, "subject",
			CURLFORM_COPYCONTENTS, "Hello there!",
			CURLFORM_END);

		curl_formadd(&formpost, &lastptr,
			CURLFORM_COPYNAME, "text",
			CURLFORM_COPYCONTENTS, "Testing some Mailgun awesomeness!",
			CURLFORM_END);

		// 设置 URL
		curl_easy_setopt(curl, CURLOPT_URL, "https://api.mailgun.net/v3/YOUR_DOMAIN_NAME/messages");

		// 设置 Basic Auth 认证（等价于 --user 'api:YOUR_API_KEY'）
		curl_easy_setopt(curl, CURLOPT_USERPWD, "api:YOUR_API_KEY");

		// 使用 multipart/form-data
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

		// 执行请求
		res = curl_easy_perform(curl);

		// 检查返回结果
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
		else
			printf("Mail sent successfully!\n");

		// 释放内存
		curl_easy_cleanup(curl);
		curl_formfree(formpost);
	}

	curl_global_cleanup();
	return 0;

}