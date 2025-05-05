# Makefile

BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86 -I./bpf

CC=gcc
CFLAGS=-g
LDFLAGS=-lbpf -lelf

BPF_OBJ=tcp_monitor.bpf.o
USER_BIN=tcp_monitor

all: $(USER_BIN)

$(BPF_OBJ): tcp_monitor.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): tcp_monitor.c $(BPF_OBJ)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)

.PHONY: all clean
