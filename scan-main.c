
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <postgresql/libpq-fe.h>
#include <signal.h>
#include <errno.h>
#include <spawn.h>

#include "masscan_main.h"
#include "db-postgresql.h"
#include "http_conn.h"
#include "cJSON.h"
#include "tomlc17.h"

//#include "uthash.h" //哈希表库
int stop_signal = 0;
int scan_done = 1;

void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        stop_signal = 1;
        printf("收到停止信号，正在清理资源...\n");
        // 可以在这里添加清理代码
    }
}

int sign_signal_func()
{
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("无法捕获 SIGINT 信号\n");
        return 0;
    }
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        perror("无法捕获 SIGTERM 信号\n");
        return 0;
    }
    return 1;
}

int check_write(const CacheManager* manager)
{
    if (!manager) return 0;
    if (stop_signal == 1) return 1; //更改写入数据库逻辑，仅在收到停止信号或结束扫描时写入，没有写入条数限制

    return 0;
}


/**
 * 发送目标或控制信号（纯文本行协议）
 */
int send_target(int write_fd, const char* target) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s\n", target);
    size_t len = strlen(buffer);
    if (write(write_fd, buffer, len) != (ssize_t)len) {
        perror("Failed to send target");
        return 0;
    }
    return 1;
}

/**
 * 接收目标或控制信号（纯文本行协议）
 */
char* receive_target(int read_fd) {
    static char buffer[256];
    static int buffer_pos = 0;
    static int buffer_len = 0;

    // 查找缓冲区中是否有完整的行
    for (int i = buffer_pos; i < buffer_len; i++) {
        if (buffer[i] == '\n') {
            // 找到完整的行
            int line_len = i - buffer_pos;
            char* result = malloc(line_len + 1);
            if (!result) return NULL;

            memcpy(result, buffer + buffer_pos, line_len);
            result[line_len] = '\0';

            // 更新缓冲区位置
            buffer_pos = i + 1;
            if (buffer_pos >= buffer_len) {
                buffer_pos = buffer_len = 0;
            }

            return result;
        }
    }

    // 没有找到完整的行，需要读取更多数据
    if (buffer_pos > 0) {
        // 移动剩余数据到缓冲区开头
        memmove(buffer, buffer + buffer_pos, buffer_len - buffer_pos);
        buffer_len -= buffer_pos;
        buffer_pos = 0;
    }

    // 读取更多数据
    ssize_t bytes_read = read(read_fd, buffer + buffer_len, sizeof(buffer) - buffer_len - 1);
    if (bytes_read <= 0) {
        return NULL;
    }

    buffer_len += bytes_read;
    buffer[buffer_len] = '\0';

    // 递归调用查找行
    return receive_target(read_fd);
}



int main(int argc, char* argv[]) 
{

    printf("获取环境变量测试\n");
    char* env;
    env = getenv("scanner_debug");
    if (env == NULL) {
        printf("没有环境变量 scanner_debug\n");
    }

    if (env) {
        printf("DEBUG 开启\n");
    }
    printf("scanner_debug = %s\n", env);
    //if (argc != 6)
    //{
    //    printf("参数不足，只有%d\n", argc);
    //}

    toml_result_t config_result = toml_parse_file_ex("config.toml");

    //检查配置文件读取是否正常

    if (!config_result.ok) {
        fprintf(stderr, "配置文件错误\n");
        fprintf(stderr, "%s\n", config_result.errmsg);
        exit(1);
    }

    //从配置文件读取扫描器配置
    toml_datum_t server = toml_seek(config_result.toptab, "scanner.c_server");
    toml_datum_t port = toml_seek(config_result.toptab, "scanner.c_port");
    toml_datum_t rate = toml_seek(config_result.toptab, "scanner.rate");

    //从配置文件读取邮件通知配置
    toml_datum_t api = toml_seek(config_result.toptab, "email_notify.api");
    toml_datum_t send_email = toml_seek(config_result.toptab, "email_notify.send_email");
    toml_datum_t email = toml_seek(config_result.toptab, "email_notify.email");

    //从配置文件读取数据库配置
    toml_datum_t d_host = toml_seek(config_result.toptab, "database.host");
    toml_datum_t d_port = toml_seek(config_result.toptab, "database.port");
    toml_datum_t d_name = toml_seek(config_result.toptab, "database.db_name");
    toml_datum_t d_username = toml_seek(config_result.toptab, "database.username");
    toml_datum_t d_password = toml_seek(config_result.toptab, "database.password");


    if (server.type != TOML_STRING) {
        fprintf(stderr, "server.type 不为 string\n");
        toml_free(config_result);
        exit(1);
    }
    printf("scanner.c_server = %s\n", server.u.s);


    if (port.type != TOML_INT64) {
        fprintf(stderr, "port.type 不为 int64\n");
        toml_free(config_result);
        exit(1);
    }
    printf("scanner.c_port = %ld\n", port.u.int64);


    if (rate.type != TOML_INT64) {
        fprintf(stderr, "rate.type 不为 int64\n");
        toml_free(config_result);
        exit(1);
    }
    printf("scanner.rate = %ld\n", rate.u.int64);


    if (api.type != TOML_STRING) {
        fprintf(stderr, "api.type 不为 string\n");
        toml_free(config_result);
        exit(1);
    }
    printf("email_notify.api = %s\n", api.u.s);

    if (send_email.type != TOML_STRING) {
        fprintf(stderr, "send_email.type 不为 string\n");
        toml_free(config_result);
        exit(1);
    }
    printf("email_notify.send_email = %s\n", send_email.u.s);

    if (email.type != TOML_STRING) {
        fprintf(stderr, "email.type 不为 string\n");
        toml_free(config_result);
        exit(1);
    }

    printf("email_notify.email = %s\n", email.u.s);

    if (d_host.type != TOML_STRING) {
        fprintf(stderr, "[database] => host 字段错误\n");
        toml_free(config_result);
        exit(1);
    }

    if (d_port.type != TOML_INT64) {
        fprintf(stderr, "[database] => port 字段错误\n");
        toml_free(config_result);
        exit(1);
    }

    if (d_name.type != TOML_STRING) {
        fprintf(stderr, "[database] => name 字段错误\n");
        toml_free(config_result);
        exit(1);
    }

    printf("database.host = %s\ndatabase.port = %ld\ndatabase.db_name = %s\n", d_host.u.s, d_port.u.int64, d_name.u.s);

    if (d_username.type != TOML_STRING) {
        fprintf(stderr, "[database] => username 字段错误\n");
        toml_free(config_result);
        exit(1);
    }
    printf("database.username = %s\n", d_username.u.s);

    if (d_password.type != TOML_STRING) {
        fprintf(stderr, "[database] => password 字段错误");
        toml_free(config_result);
        exit(1);
    }
    printf("\n\n通过所有检查\n\n");


	setbuf(stdout, NULL); // 禁用缓冲，确保输出立即显示
    if (!sign_signal_func()) return 0;                    //注册信号处理函数
    printf("启动中\n");

    CacheManager* manager = create_cache_manager();
    DbConnectInfo db_info;
    db_info.ip = d_host.u.s;                // 主机地址
    db_info.port = d_port.u.int64;          // 端口
    db_info.db_type = 0;                    // 数据库类型，0为postgresql
    db_info.db_name = d_name.u.s;           // 数据库名称
    db_info.username = d_username.u.s;      // 用户名
    db_info.password = d_password.u.s;      // 密码
    PGconn* conn = create_conn(&db_info);
    if (!conn)
    {
        clear_cache_manager(manager);
        exit(1);
    }
    printf("开始初始数据库\n");
    if (!postgresql_init(conn))
    {
        clear_cache_manager(manager);
        PQfinish(conn);
        exit(1);
    }

    ScanData* data = malloc(sizeof(ScanData));
    if (!data)
    {
		fprintf(stderr, "Masscan data内存分配失败\n");
        clear_cache_manager(manager);
        PQfinish(conn);
        exit(1);
    } 
    printf("分配scan data成功\n");
	//ScanConfig* scan_config = malloc(sizeof(ScanConfig));

 //   if (!scan_config)
 //   {
 //       free(data);
 //       PQfinish(conn);
 //       clear_cache_manager(manager);
 //       exit(1);
 //   }
 //   printf("分配scan config成功\n");

    //移除了scan_config
    //scan_config->target_ip = strdup(argv[1]);
    //scan_config->target_port = strdup(argv[2]);
    //scan_config->scanner_path = strdup(argv[5]);
    //scan_config->banner_scan_ip = strdup(argv[4]);
    //scan_config->rate = strdup(argv[3]);

    //if (!check_scan_config(scan_config))
    //{
    //    free_scan_config(scan_config);
    //    free(data);
    //    PQfinish(conn);
    //    clear_cache_manager(manager);
    //    exit(1);
    //}
    
    if (!stop_signal)
    {
        scan(conn, data, manager);
        printf("扫描完成\n");
    }
    

    /**
    * 清理分配的内存
    */
    free(data);
    PQfinish(conn);
    clear_cache_manager(manager);
    toml_free(config_result);
    //free_scan_config(scan_config);
    printf("垃圾清理完毕\n");

    return 0;
}



// 新增函数：直接从文件描述符读取而不是FILE*
int scan_output_format_fd(PGconn* conn, int fd, ScanData* data, CacheManager* manager, const char* scanner_name)
{
    char buffer[8192];
    char line_buffer[8192];
    int line_pos = 0;
    sleep(1); //暂停2秒

    while (!stop_signal)
    {
        ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) {
            sleep(1); // 休眠一秒后重新读取
            continue; // 没有数据可读，继续
        }

        buffer[bytes_read] = '\0';
        
        // 处理接收到的数据，按行分割
        for (int i = 0; i < bytes_read; i++)
        {
            if (buffer[i] == '\n')
            {
                line_buffer[line_pos] = '\0';

                // 处理完整的一行
                if (!strncmp(line_buffer, "Banner", 6))
                {
                    // 将banner清空，避免脏数据污染
                    memset(data->banner, 0, sizeof(data->banner));
                    unsigned int port;
                    //char protocol[10], ipv4[16], service[128], banner[7168];
                    if (sscanf(line_buffer, "Banner %u %9s %39s %127s %7167[^\n]", &data->port, data->protocol, data->ip, data->service, data->banner) == 5)
                    {
                        if (stop_signal) return 0;

                        if (check_write(manager)) {
                            if (!write_to_database(conn, manager)) return 0;
                        }
                        else {
                            if (!add_scan_result_to_cache(manager, data->ip, scanner_name, data->port, data->service, data->protocol, data->banner)) return 0;
                        }
                    }
                }
                else if (!strncmp(line_buffer, "COMPLETE", 8))
                {
                    if (!write_to_database(conn, manager)) return 0;
                    scan_done = 1;
                    return 1;
                }
                else if (!strncmp(line_buffer, "ERROR", 5))
                {
                    printf("收到 ERROR\n");
                    stop_signal = 1;
                    return 0;
                }
                else if (!strncmp(line_buffer, "DONE_OK", 7))
                {
                    printf("收到DONE_OK\n");
                    stop_signal = 1;
                    return 1;
                }

                line_pos = 0;
            }
            else {
                if (line_pos < sizeof(line_buffer) - 1) {
                    line_buffer[line_pos++] = buffer[i];
                }
            }
        } //for
    } //while

    return 1;
}

/*
先创建一个子线程，然后在子线程中执行扫描
*/
int scan(PGconn* conn, ScanData* ScanData, CacheManager* manager)
{
    pid_t pid;
    int parent_to_child[2];
    int child_to_parent[2];

    // 创建管道
    if (pipe(parent_to_child) == -1 || pipe(child_to_parent) == -1) {
        perror("创建管道失败");
        return 0;
    }

    pid = fork();
    if (pid == -1) {
        perror("创建子进程失败");
        return 0;
    }

    if (pid == 0) { // 子进程
        close(parent_to_child[1]);
        close(child_to_parent[0]);

        // 重定向标准输出和错误输出
        dup2(child_to_parent[1], STDOUT_FILENO);
        //dup2(child_to_parent[1], STDERR_FILENO);
        close(child_to_parent[1]);
        setbuf(stdout, NULL);
        static unsigned int scan_seed = 1;
        sleep(1); //等待1秒
        int wait_n = 0;  //重试期间等待次数，避免大量无用输出
        while (!stop_signal) {
            char* target = receive_target(parent_to_child[0]);
            if (!target) {
                wait_n += 1;
                fprintf(stderr, "Failed to receive target: %s\n", strerror(errno));
                if (wait_n < 10) {
                    sleep(wait_n * 2);
                }
                else {
                    //当重试10次以上后直接退出
                    send_stop_email(); //发送停止提示邮件
                    stop_signal = 1;
                }
                continue;
            }


            if (!strcmp(target, "DONE")) {

                free(target);
                printf("DONE_OK\n");
                fflush(stdout);
                break;  // 跳出循环但不退出进程
            }

            //删除了masscan种子

            //char seed_str[16];
            //snprintf(seed_str, sizeof(seed_str), "%u", scan_seed++);

            // 执行扫描
            pid_t child_pid;
            posix_spawn_file_actions_t actions;
            posix_spawnattr_t attr;
            int status;

            if (posix_spawn_file_actions_init(&actions) != 0) {
                fprintf(stderr, "posix_spawn_file_actions_init错误\n");
                printf("ERROR\n");
                fflush(stdout);
                free(target);
                continue;
            }

            if (posix_spawnattr_init(&attr) != 0) {
                posix_spawn_file_actions_destroy(&actions);
                printf("ERROR\n");
                fprintf(stderr, "posix_spawnattr_init错误\n");
                fflush(stdout);
                free(target);
                continue;
            }

            if (posix_spawnattr_setflags(&attr, 0) != 0) {
                posix_spawn_file_actions_destroy(&actions);
                posix_spawnattr_destroy(&attr);
                printf("ERROR\n");
                fprintf(stderr, "posix_spawnattr_setflags错误\n");
                fflush(stdout);
                free(target);
                continue;
            }

            if (posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDOUT_FILENO) != 0) {
                posix_spawn_file_actions_destroy(&actions);
                posix_spawnattr_destroy(&attr);
                printf("ERROR\n");
                fprintf(stderr, "posix_spawn_file_actions_adddup2错误\n");
                fflush(stdout);
                free(target);
                continue;
            }

            char* scan_argv[] = {
                "a",
                "-p0-65535",
                target,
                "--rate=40000",
                "--banner",
                "--source-port",
                "61000",
                NULL
            };

            status = posix_spawnp(&child_pid, "./a", &actions, &attr, scan_argv, NULL);
            // 清理资源
            posix_spawn_file_actions_destroy(&actions);
            posix_spawnattr_destroy(&attr);

            if (status != 0) {
                fprintf(stderr, "posix_spawnp failed: %s\n", strerror(status));
                printf("ERROR\n");
                fflush(stdout);
                free(target);
                continue;
            }

            // 等待子子进程完成
            if (waitpid(child_pid, &status, 0) == -1) {
                printf("ERROR\n");
                fflush(stdout);
            }
            
            else {
                if (WIFEXITED(status)) {
                    printf("COMPLETE\n");
                    fflush(stdout);
                }
                else {
                    printf("ERROR\n");
                    fflush(stdout);
                }
            }
            free(target);
        }

        close(parent_to_child[0]);
        exit(0);

    }
    else { // 父进程
        close(parent_to_child[0]);
        close(child_to_parent[1]);

        int req_count = 0;
        const char* target_domain = "http://192.168.1.6:9999/scanner/target";
        int child_exited = 0;

        while (!stop_signal && !child_exited) {
            // 检查子进程状态
            int status;
            pid_t result = waitpid(pid, &status, WNOHANG);
            if (result > 0) {
                fprintf(stderr, "Child process exited with status %d\n", WEXITSTATUS(status));
                child_exited = 1;
                break;
            }
            else if (result == -1) {
                perror("waitpid failed");
                child_exited = 1;
                break;
            }

            // 获取目标

            if (!scan_done)

            {
                sleep(1);
                continue;
            }

            scan_done = 0;

            char* http_result = http_requests(target_domain);
            if (!http_result) {
                sleep(5);
                req_count++;
                scan_done = 1;
                if (req_count >= 5) {
                    send_target(parent_to_child[1], "DONE");
                    break;
                }
                continue;
            }

            cJSON* root = cJSON_Parse(http_result);

            if (!root) {
                fprintf(stderr, "JSON parse failed\n");
                free(http_result);
                req_count++;
                scan_done = 1;
                if (req_count >= 5) {
                    send_target(parent_to_child[1], "DONE");
                    break;
                }
                continue;
            }

            //从json中获取ip参数
            cJSON* ip = cJSON_GetObjectItemCaseSensitive(root, "ip");
            if (cJSON_IsString(ip) && ip->valuestring != NULL) {
                if (!send_target(parent_to_child[1], ip->valuestring)) {
                    fprintf(stderr, "Failed to send target: %s\n", ip->valuestring);
                    cJSON_Delete(root);
                    free(http_result);
                    break;
                }
                req_count = 0;
            }
            else {
                fprintf(stderr, "Invalid IP in JSON\n");
                req_count++;
                scan_done = 1;
                if (req_count >= 5) {
                    send_target(parent_to_child[1], "DONE");
                    break;
                }
            }

            cJSON_Delete(root);
            free(http_result);

            // 处理扫描输出 - 修改为直接从文件描述符读取
            if (!scan_output_format_fd(conn, child_to_parent[0], ScanData, manager, "masscan")) {
                printf("scan_output_format 失败，退出\n");
                clear_cache_data(manager);
                close(parent_to_child[1]);
                wait(NULL);
                return 0;
            }
        }

        // 确保发送DONE信号（如果还没发送）
        if (!child_exited) {
            printf("主循环结束，发送DONE信号给子进程\n");
            send_target(parent_to_child[1], "DONE");
        }
        req_count = 0;

        close(parent_to_child[1]);
        close(child_to_parent[0]);
        clear_cache_data(manager);
        // 等待子进程彻底结束
        if (!child_exited) {
            wait(NULL);
        }
    }

    return 1;
}


//int check_scan_config(ScanConfig* scan_config)
//{
//    if (!scan_config->target_ip || !scan_config->target_port || !scan_config->scanner_path || !scan_config->banner_scan_ip || !scan_config->rate)
//    {
//        return 0;
//    }
//    return 1;
//}

//int free_scan_config(ScanConfig* scan_config)
//{
//    if (scan_config->target_ip) free(scan_config->target_ip);
//    if (scan_config->target_port) free(scan_config->target_port);
//    if (scan_config->scanner_path) free(scan_config->scanner_path);
//    if (scan_config->banner_scan_ip) free(scan_config->banner_scan_ip);
//    if (scan_config->rate) free(scan_config->rate);
//    return 1;
//}

