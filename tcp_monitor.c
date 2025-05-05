#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include "conn_info.h"

#define PINNED_MAP_PATH "/sys/fs/bpf/tcp_monitor_whitelist"

static volatile bool exiting = false;

struct handler_ctx {
    int whitelist_map_fd;
};


static void print_usage(const char *prog) 
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -d, --daemon    Run as daemon\n");
    printf("  -l, --list      List current whitelist and exit\n");
    printf("  -h, --help      Display this help message\n");
}


void add_to_whitelist(int map_fd, int port, const char *comm) 
{
    struct whitelist_key key = { .port = port };
    strncpy(key.comm, comm, TASK_COMM_LEN);
    __u32 value = 1;
    
    if( bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0 )
        fprintf(stderr, "Failed to add whitelist entry: %s\n", strerror(errno));
    else
        printf("Whitelisted: port %d for %s\n", port, comm);
}


bool is_process_whitelisted(int map_fd, int port, const char *comm) 
{
    struct whitelist_key key = { .port = port };
    strncpy(key.comm, comm, TASK_COMM_LEN);
    __u32 value;
    return bpf_map_lookup_elem(map_fd, &key, &value) == 0;
}


void print_whitelist(int map_fd) 
{
    struct whitelist_key key = {}, next_key;
    __u32 value;
    int err;

    printf("Current Whitelist:\n");
    printf("PORT\tPROCESS\n");
    printf("----\t-------\n");

    while( true ) 
    {
        err = bpf_map_get_next_key(map_fd, &key, &next_key);
        if( err ) 
        {
            if( errno == ENOENT )
                break;  // No more entries

            fprintf(stderr, "Error getting next key: %s\n", strerror(errno));
            return;
        }

        key = next_key;
        if( bpf_map_lookup_elem(map_fd, &key, &value) == 0 )
            printf("%d\t%s\n", key.port, key.comm);
    }
}


int handle_event(void *ctx, void *data, size_t data_sz) 
{
    struct handler_ctx *h_ctx = ctx;
    struct conn_info *e = data;

    if( !is_process_whitelisted(h_ctx->whitelist_map_fd, e->dport, e->comm) ) 
    {
        printf("BLOCKED: PID %d (%s) connected to port %d\n", e->pid, e->comm, e->dport);
        if( kill(e->pid, SIGKILL) != 0 )
            fprintf(stderr, "Failed to kill PID %d: %s\n", e->pid, strerror(errno));
    } 
    else 
    {
        printf("ALLOWED: PID %d (%s) connected to port %d\n", e->pid, e->comm, e->dport);
    }

    return 0;
}


static void sigint_handler(int signo) 
{
    exiting = true;
}


int main(int argc, char **argv) 
{
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct bpf_map *whitelist_map;
    int map_fd, whitelist_map_fd, err;
    int daemonize = 0, list_only = 0;
    struct handler_ctx ctx;

    static const struct option long_options[] = {
        { "daemon", no_argument, NULL, 'd' },
        { "list", no_argument, NULL, 'l' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while( true ) 
    {
        int opt = getopt_long(argc, argv, "dlh", long_options, NULL);
        if( opt == -1 )
            break;

        switch (opt) {
        case 'd':
            daemonize = 1;
            break;
        case 'l':
            list_only = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    obj = bpf_object__open_file("tcp_monitor.bpf.o", NULL);
    if( libbpf_get_error(obj) ) 
    {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if( err ) 
    {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        goto cleanup;
    }

    whitelist_map = bpf_object__find_map_by_name(obj, "whitelist");
    if( !whitelist_map ) 
    {
        fprintf(stderr, "Failed to find whitelist map\n");
        goto cleanup;
    }

    // Pin the map before we get its file descriptor
    if( bpf_map__pin(whitelist_map, PINNED_MAP_PATH) ) 
    {
        fprintf(stderr, "Failed to pin whitelist map\n");
        goto cleanup;
    }

    whitelist_map_fd = bpf_map__fd(whitelist_map);

    // Initialize with some default whitelist entries
    add_to_whitelist(whitelist_map_fd, 22, "sshd");
    add_to_whitelist(whitelist_map_fd, 80, "firefox");
    add_to_whitelist(whitelist_map_fd, 443, "firefox");

    if( list_only ) 
    {
        print_whitelist(whitelist_map_fd);
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_tcp_connect");
    if( !prog ) 
    {
        fprintf(stderr, "Failed to find BPF program\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if( libbpf_get_error(link) ) 
    {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if( map_fd < 0 ) 
    {
        fprintf(stderr, "Failed to find events map\n");
        goto cleanup;
    }

    ctx.whitelist_map_fd = whitelist_map_fd;
    rb = ring_buffer__new(map_fd, handle_event, &ctx, NULL);
    if( !rb ) 
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    if( daemonize ) 
    {
        printf("Daemonizing...\n");
        if( daemon(0, 0) ) 
        {
            perror("daemon");
            goto cleanup;
        }
    }

    printf("TCP Connection Monitor started. Current whitelist:\n");
    print_whitelist(whitelist_map_fd);
    printf("\nWhitelist management:\n");
    printf("  Use 'whitelist_cli add <port> <comm>' to allow access\n");
    printf("  Use 'whitelist_cli del <port> <comm>' to revoke access\n");
    printf("  Use 'whitelist_cli list' to view current whitelist\n");
    printf("Press Ctrl+C to exit.\n");

    while( !exiting ) 
    {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if( err == -EINTR ) 
        {
            err = 0;
            break;
        }
        if( err < 0 ) 
        {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }


cleanup:
    if( rb ) 
        ring_buffer__free(rb);
    if( link ) 
        bpf_link__destroy(link);
    if( obj ) 
        bpf_object__close(obj);
    if( whitelist_map ) 
        bpf_map__unpin(whitelist_map, PINNED_MAP_PATH);

    return err != 0;
}