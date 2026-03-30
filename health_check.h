#include "cJSON.h"
/*
* 该函数主要用于测试目标获取是否正常
* 函数接收多个参数，其中 test_url 为获取目标的 url
* 函数返回一个 int 值，当一切正常时返回1，否则返回0
*/
int get_target_test(const char *test_url);

/*
* 该函数用于检查获取到的目标数据
* 返回 int 类型，0 代表发生了错误，1 为一切正确，并且会把获取到的数据写入传入指针所指向的内存中
* 接收 2 个参数，分别为：json 根和模式（当 mode 为 0 时代表扫描中的检查，为 1 时代表处于健康检查模式）
*/
int check_target(const cJSON *root, const cJSON **ip, const cJSON **port, const cJSON **source_port, const cJSON **rate, const int mode);