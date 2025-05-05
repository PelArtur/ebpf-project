#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include "conn_info.h"

#define PINNED_MAP_PATH "/sys/fs/bpf/tcp_monitor_whitelist"

void print_usage(const char *prog) 
{
    printf("Usage: %s <command> [args]\n", prog);
    printf("Commands:\n");
    printf("  add <port> <comm>    - Whitelist a process for a port\n");
    printf("  del <port> <comm>    - Remove whitelist for a process on port\n");
    printf("  list                 - List all whitelisted ports\n");
    printf("  list <port>          - Show whitelist for specific port\n");
}

int list_all_entries(int map_fd) 
{
    struct whitelist_key key = {}, next_key;
    __u32 value;
    int err;

    printf("Whitelisted ports and processes:\n");
    printf("PORT\tPROCESS\n");
    printf("----\t-------\n");

    err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    if( err ) 
    {
        if( errno == ENOENT ) 
        {
            printf("No whitelist entries found\n");
            return 0;
        }

        fprintf(stderr, "Error getting first key: %s\n", strerror(errno));
        return -1;
    }

    do 
    {
        key = next_key;
        if( bpf_map_lookup_elem(map_fd, &key, &value) == 0 )
            printf("%d\t%s\n", key.port, key.comm);

        err = bpf_map_get_next_key(map_fd, &key, &next_key);
        if( err && errno != ENOENT ) 
        {
            fprintf(stderr, "Error getting next key: %s\n", strerror(errno));
            return -1;
        }
    } while( !err );

    return 0;
}

int list_port_entries(int map_fd, int port) 
{
    struct whitelist_key key = {}, next_key;
    __u32 value;
    int found = 0;

    printf("Whitelisted processes for port %d:\n", port);
    printf("PROCESS\n");
    printf("-------\n");

    int err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    if( err ) 
    {
        if( errno == ENOENT ) 
        {
            printf("No whitelist entries found\n");
            return 0;
        }

        fprintf(stderr, "Error getting first key: %s\n", strerror(errno));
        return -1;
    }

    do 
    {
        key = next_key;
        if( key.port == port && bpf_map_lookup_elem(map_fd, &key, &value) == 0 ) 
        {
            printf("%s\n", key.comm);
            found = 1;
        }

        err = bpf_map_get_next_key(map_fd, &key, &next_key);
        if( err && errno != ENOENT ) 
        {
            fprintf(stderr, "Error getting next key: %s\n", strerror(errno));
            return -1;
        }
    } while( !err );

    if( !found )
        printf("No whitelist entries for port %d\n", port);

    return 0;
}

int main(int argc, char **argv) 
{
    if( argc < 2 ) 
    {
        print_usage(argv[0]);
        return 1;
    }

    // Access the pinned map directly
    int map_fd = bpf_obj_get(PINNED_MAP_PATH);
    if( map_fd < 0 ) 
    {
        fprintf(stderr, "Failed to access whitelist map: %s\n", strerror(errno));
        fprintf(stderr, "Is tcp_monitor running?\n");
        return 1;
    }

    const char *action = argv[1];
    int ret = 0;

    if( strcmp(action, "list") == 0 ) 
    {
        if( argc == 2 ) 
        {
            ret = list_all_entries(map_fd);
        } 
        else if( argc == 3 ) 
        {
            int port = atoi(argv[2]);
            ret = list_port_entries(map_fd, port);
        } 
        else 
        {
            fprintf(stderr, "Invalid arguments for list command\n");
            print_usage(argv[0]);
            ret = 1;
        }
    } 
    else if( strcmp(action, "add") == 0 ) 
    {
        if( argc != 4 ) 
        {
            fprintf(stderr, "Invalid arguments for add command\n");
            print_usage(argv[0]);
            ret = 1;
        } 
        else 
        {
            int port = atoi(argv[2]);
            const char *comm = argv[3];
            struct whitelist_key key = { .port = port };
            strncpy(key.comm, comm, TASK_COMM_LEN);
            __u32 value = 1;

            if( bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0 ) 
            {
                fprintf(stderr, "Add failed: %s\n", strerror(errno));
                ret = 1;
            } 
            else 
            {
                printf("Added port %d comm %s\n", port, comm);
            }
        }
    }
    else if( strcmp(action, "del") == 0 ) 
    {
        if( argc != 4 ) 
        {
            fprintf(stderr, "Invalid arguments for del command\n");
            print_usage(argv[0]);
            ret = 1;
        } 
        else 
        {
            int port = atoi(argv[2]);
            const char *comm = argv[3];
            struct whitelist_key key = { .port = port };
            strncpy(key.comm, comm, TASK_COMM_LEN);

            __u32 value;
            if( bpf_map_lookup_elem(map_fd, &key, &value) != 0 ) 
            {
                fprintf(stderr, "Entry not found: port %d comm %s\n", port, comm);
                ret = 1;
            } 
            else 
            {
                if( bpf_map_delete_elem(map_fd, &key) != 0 ) 
                {
                    fprintf(stderr, "Delete failed: %s\n", strerror(errno));
                    ret = 1;
                } 
                else 
                {
                    printf("Deleted port %d comm %s\n", port, comm);
                }
            }
        }
    }
    else 
    {
        fprintf(stderr, "Invalid command\n");
        print_usage(argv[0]);
        ret = 1;
    }

    close(map_fd);
    return ret;
}