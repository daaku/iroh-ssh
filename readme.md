# iroh-ssh

Reach an ssh server by endpoint id instead of IP address, through NATs and firewalls.

Binaries: [latest release](../../releases/latest)

## Server

Run this next to your ssh server, under whatever keeps it running:

```sh
iroh-ssh server --persist
```

It prints the endpoint id, which stays the same across restarts.

### macOS service

Turn on Remote Login in System Settings → General → Sharing, then install the
binary (Apple Silicon):

```sh
sudo mkdir -p /usr/local/bin
sudo curl -fLo /usr/local/bin/iroh-ssh https://github.com/daaku/iroh-ssh/releases/latest/download/iroh-ssh-aarch64-apple-darwin
sudo chmod 755 /usr/local/bin/iroh-ssh
```

Run it as a launch daemon rather than a launch agent: daemons start at boot,
agents only once someone logs in. After `sudo fdesetup authrestart` the disk is
unlocked but the Mac waits at the login window, so only a daemon will be
running. It runs as your user and keeps its key in your `~/.ssh`, like running
it by hand would:

```sh
sudo tee /Library/LaunchDaemons/org.daaku.iroh-ssh.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.daaku.iroh-ssh</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/iroh-ssh</string>
        <string>server</string>
        <string>--persist</string>
    </array>
    <key>UserName</key>
    <string>$USER</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/Library/Logs/iroh-ssh.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/Library/Logs/iroh-ssh.log</string>
</dict>
</plist>
EOF
sudo launchctl enable system/org.daaku.iroh-ssh
sudo launchctl bootstrap system /Library/LaunchDaemons/org.daaku.iroh-ssh.plist
```

This starts it now and on every boot. The endpoint id and any warnings go to
`~/Library/Logs/iroh-ssh.log`.

Reboot with `sudo fdesetup authrestart` to keep it reachable. With FileVault on,
a plain restart stops at the disk unlock screen, before anything starts.

After replacing the binary, restart the service with
`sudo launchctl kickstart -k system/org.daaku.iroh-ssh`. To remove it:

```sh
sudo launchctl bootout system/org.daaku.iroh-ssh
sudo rm /Library/LaunchDaemons/org.daaku.iroh-ssh.plist
```

## Client

In `~/.ssh/config`:

```
Host my-server
    ProxyCommand iroh-ssh proxy <endpoint id>
```

Then `ssh my-server`.
