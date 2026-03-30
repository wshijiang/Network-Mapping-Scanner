#include <string.h>
#include "tomlc17.h"

struct config_field_t
{
	const char *key;
	toml_type_t value;
};


int loading_config(toml_result_t *config_result, const char *filename, int hot_reloading);