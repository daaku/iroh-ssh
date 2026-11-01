# iroh-ssh

Reach an ssh server by endpoint id instead of IP address, through NATs and firewalls.

Binaries: [latest release](../../releases/latest)

## Server

Run this next to your ssh server, under whatever keeps it running:

```sh
iroh-ssh server --persist
```

It prints the endpoint id, which stays the same across restarts.

## Client

In `~/.ssh/config`:

```
Host my-server
    ProxyCommand iroh-ssh proxy <endpoint id>
```

Then `ssh my-server`.
