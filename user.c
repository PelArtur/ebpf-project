#include <bpf/libbpf.h>
#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static volatile bool exiting = false;

void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL, *tmp;
    struct bpf_link *link = NULL;
    int err;

    // Obtain the interface index of "eth0"
    int eth0_index = if_nametoindex("eth0");
    if (eth0_index == 0) {
        perror("if_nametoindex");
        return 1;
    }
    printf("eth0 interface index (from user-space): %d\n", eth0_index);

    // Open the BPF object file (ensure "tcp.o" is in the current directory)
    obj = bpf_object__open_file("tcp.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file: %s\n",
                strerror(-libbpf_get_error(obj)));
        return 1;
    }
    
    // Load the BPF object into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %d\n", err);
        return 1;
    }

    // Debug: iterate over all programs in the object and print their section names.
    printf("Listing loaded BPF programs:\n");
    bpf_object__for_each_program(tmp, obj) {
        const char *section = bpf_program__section_name(tmp);
        printf("  Found program section: %s\n", section);
    }

    // Instead of using bpf_object__find_program_by_name,
    // manually iterate over the programs to find the one with the matching section.
    bpf_object__for_each_program(tmp, obj) {
        if (strcmp(bpf_program__section_name(tmp), "kprobe/tcp_v4_connect") == 0) {
            prog = tmp;
            break;
        }
    }
    if (!prog) {
        fprintf(stderr, "Error: Cannot find program with section 'kprobe/tcp_v4_connect'\n");
        goto cleanup;
    }

    // Attach the program
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Error attaching BPF program: %s\n",
                strerror(-libbpf_get_error(link)));
        link = NULL;
        goto cleanup;
    }

    // Setup signal handlers for graceful termination.
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("BPF program loaded and attached. Press Ctrl+C to exit.\n");
    
    // Main loop.
    while (!exiting) {
        sleep(1);
    }
    printf("Exiting...\n");

cleanup:
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
        
    return err != 0;
}

