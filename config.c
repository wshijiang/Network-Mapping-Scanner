#include "config.h"


/** 用于验证配置文件中的各条目是否正确
* 成功返回正确的条目数，失败返回 -1
* 函数接受四个参数，
*/

int valid_config_fields(
	const toml_datum_t *table,
	const struct config_field_t *field,
	const char *section,
	size_t count
) {
	char key_path[64];
	size_t counts = 0;


	for (size_t i = 0; i < count; i++) {
		int len = snprintf(key_path, sizeof(key_path), "%s%s", section, field[i].key);

		if (len < 0) {
			fprintf(stderr, "配置文件字段编码出现错误，返回值：%d\n\t错误 [%s] => %s\n", len, section, field[i].key);

			/* 当 snprintf 函数返回值为负值时代表出现了编码相关的错误 */
			return len;
		} else if ((size_t)len > sizeof(key_path)) {
			fprintf(stderr, "配置文件字段 key 因过长被截断，len：%d\n\t错误 [%s] => %s\n", len, section, field[i].key);
			return -1;
		}

		toml_datum_t tmp = toml_seek(*table, key_path);
		if (tmp.type != field[i].value) {
			fprintf(stderr, "配置文件字段类型错误，错误 [%s] => %s\n", section, field[i].key);
			return -1;
		}
		++counts;
	}

	return counts;
}

/** 加载配置文件，并且可以选择是否热加载
 * 当成功时返回非零值，失败则返回 -1
 * 函数接受 3 个参数，分别表示存放配置文件地址的指针、配置文件名、是否热重载（值为非零时启用热重载，且只有部分参数支持热重载）
*/
int loading_config(toml_result_t *config_result, const char *filename, int hot_reloading)
{
	struct config_field_t scanner_config[] = {
		{"c_server", TOML_STRING},
		{"c_port", TOML_INT64},
		{"rate", TOML_INT64}
	};

	struct config_field_t email_notify_config[] = {
		{"api", TOML_STRING},
		{"send_email", TOML_STRING},
		{"email", TOML_STRING}
	};

	struct config_field_t database_config[] = {
		{"host", TOML_STRING},
		{"port", TOML_INT64},
		{"db_name", TOML_STRING},
		{"username", TOML_STRING},
		{"password", TOML_STRING}
	};



	*config_result = toml_parse_file_ex(filename);

	if (!config_result->ok) {
		fprintf(stderr, "读取配置文件错误：%s\n", config_result->errmsg);
		return -1;
	}

	if (valid_config_fields(&config_result->toptab, scanner_config, "scanner.", 3) != 3) {
		return -1;
	}
	if (valid_config_fields(&config_result->toptab, email_notify_config, "email_notify.", 3) != 3) {
		return -1;
	}
	if (valid_config_fields(&config_result->toptab, database_config, "database.", 5) != 5) {
		return -1;
	}
	return 1;
}