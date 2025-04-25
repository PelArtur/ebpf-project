# ebpf-project

```
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I./bpf -c tcp_monitor.bpf.c -o tcp_monitor.bpf.o
```

```
gcc tcp_monitor.c -o tcp_monitor -lbpf -lelf
```

```
sudo ./tcp_monitor
```