BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86 -I./

CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-lbpf -lelf -lz

BPF_OBJ=tcp_monitor.bpf.o
USER_BIN=tcp_monitor
CLI_BIN=whitelist_cli
BTF_HEADER=vmlinux.h

all: $(USER_BIN) $(CLI_BIN)

$(BTF_HEADER):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): tcp_monitor.bpf.c $(BTF_HEADER)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): tcp_monitor.c $(BPF_OBJ)
	$(CC) $(CFLAGS) tcp_monitor.c -o $@ $(LDFLAGS)

$(CLI_BIN): cli.c $(BPF_OBJ)
	$(CC) $(CFLAGS) cli.c -o $@ $(LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN) $(CLI_BIN) $(BTF_HEADER)

.PHONY: all clean
