#include <bpf/libbpf.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

#define TASK_COMM_LEN 16

static volatile bool exiting = false;

struct conn_info 
{
    __u32 pid;
    __u16 dport;
    char comm[TASK_COMM_LEN];
};


void handle_event(void *ctx, void *data, size_t data_sz) 
{
    struct conn_info *e = data;
    printf("PID %d (%s) connected to port %d\n", e->pid, e->comm, e->dport);
}


static void sigint_handler(int signo) 
{
    exiting = true;
}


int main() 
{
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int map_fd, err;

    signal(SIGINT, sigint_handler);

    obj = bpf_object__open_file("tcp_monitor.bpf.o", NULL);
    if( libbpf_get_error(obj) ) 
    {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if( err ) 
    {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_tcp_connect");
    if( !prog ) 
    {
        fprintf(stderr, "Failed to find handle_tcp_connect program\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if( libbpf_get_error(link) ) 
    {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if( map_fd < 0 ) 
    {
        fprintf(stderr, "Failed to find events map\n");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if( !rb ) 
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for TCP connections... Press Ctrl+C to exit.\n");

    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
