CC := gcc
LDFLAGS := -lcurl -lpq
CFLAGS := -Wall -O2 -MMD -MP

TARGET := scanner

SRC_DIR := .
OBJ_DIR := build

SRCS := \
	scan-main.c \
	http_conn.c \
	tomlc17.c \
	scaninfo-cache.c \
	db-postgresql.c \
	cJSON.c \
	time-and-json.c \
	config.c \
	health_check.c \
	cargs.c \
	log.c


OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

$(info DEBUG = $(DEBUG))

ifeq ($(DEBUG), 1)
  CFLAGS += -g
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)
	

$(OBJ_DIR)/%.o : %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@


$(OBJ_DIR): 
	mkdir -p $(OBJ_DIR)

-include $(DEPS)
	


.PHONY: all clean

clean: 
	rm -rf $(OBJ_DIR)