#ifndef CONN_INFO_H
#define CONN_INFO_H

#define TASK_COMM_LEN 64
#define MAX_WHITELIST 100

struct conn_info {
    __u32 pid;
    __u16 dport;
    char comm[TASK_COMM_LEN];
};

struct whitelist_key {
    int port;
    char comm[TASK_COMM_LEN];
};

#endif // CONN_INFO_H