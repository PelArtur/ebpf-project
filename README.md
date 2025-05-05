# ebpf-project

Compiling:

```bash
make
```

Running:
```bash
sudo ./tcp_monitor
```

```
sudo ./whitelist_cli <command> [args]
Commands:
  add <port> <comm>    - Whitelist a process for a port
  del <port> <comm>    - Remove whitelist for a process on port
  list                 - List all whitelisted ports
  list <port>          - Show whitelist for specific port
```
