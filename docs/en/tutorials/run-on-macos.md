# Run on macOS

## Install Homebrew

### For x86

Install Homebrew using the [official instructions](https://docs.brew.sh/Installation):

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

### For ARM64

To install ARM64 packages, install Homebrew in `/opt/homebrew`:

```shell
cd /opt
sudo mkdir homebrew
sudo chown $(whoami):admin homebrew
curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip 1 -C homebrew
```

## Lima

### Setup

Run dae in a [Lima](https://github.com/lima-vm/lima) virtual machine to proxy the
macOS host's entire network.

#### 1. Install Lima and socket_vmnet

```shell
# Install lima for VM and socket_vmnet for bridge.
brew install lima socket_vmnet

# Set up the sudoers file for launching socket_vmnet from Lima
limactl sudoers >etc_sudoers.d_lima
sudo install -o root etc_sudoers.d_lima /etc/sudoers.d/lima
```

#### 2. Configure Lima and the dae VM

```shell
# Configure lima networks.
socket_vmnet_bin=$(readlink -f ${HOMEBREW_PREFIX}/opt/socket_vmnet)/bin/socket_vmnet
sed -ir "s#^ *socketVMNet:.*#  socketVMNet: \"${socket_vmnet_bin}\"#" ~/.lima/_config/networks.yaml
```

```shell
# Configure dae vm.
mkdir ~/.lima/dae/
cat << 'EOF' | tee ~/.lima/dae/lima.yaml
images:
- location: "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
  arch: "x86_64"
- location: "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.qcow2"
  arch: "aarch64"
mounts:
networks:
- lima: bridged
  interface: "lima0"
memory: "1GB"
disk: "3GiB"
EOF
```

#### 3. Start and configure the dae VM

```shell
# Start dae VM.
limactl start dae
```

```shell
# Enter the dae VM.
limactl shell dae

# Manually configure network.
cat << 'EOF' | sudo tee /etc/netplan/99-override.yaml
network:
    ethernets:
        eth0:
            dhcp4: true
            dhcp4-overrides:
                route-metric: 200
        lima0:
            dhcp4: true
            dhcp6: true
    version: 2
EOF

# Apply netplan.
sudo netplan apply

# Install requirements.
sudo apt-get install jq

# Install dae.
sudo bash -c "$(curl -s https://hubmirror.v2raya.org/raw/daeuniverse/dae-installer/main/installer.sh)" @ install

# Configure config.dae.
cat << 'EOF' | sudo tee /usr/local/etc/dae/config.dae
global {
  lan_interface: lima0
  wan_interface: lima0

  log_level: info
  allow_insecure: false
  auto_config_kernel_parameter: true
}

subscription {
  # Fill in your subscription links here.
}

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/dns.md for full examples.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    request {
      fallback: alidns
    }
    response {
      upstream(googledns) -> accept
      ip(geoip:private) && !qname(geosite:cn) -> googledns
      fallback: accept
    }
  }
}

group {
  proxy {
    #filter: name(keyword: HK, keyword: SG)
    policy: min_moving_avg
  }
}

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md for full examples.
routing {
  pname(NetworkManager) -> direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  ### Write your rules below.

  dip(geoip:private) -> direct
  dip(geoip:cn) -> direct
  domain(geosite:cn) -> direct

  fallback: proxy
}
EOF
sudo chmod 0600 /usr/local/etc/dae/config.dae

# Do not forget to add your subscriptions and nodes.
sudo vim /usr/local/etc/dae/config.dae

# Enable and start dae.
sudo systemctl enable --now dae.service

# Exit dae vm.
exit
```

#### 4. Set the macOS default route to the dae VM

> **Note**
> You may need to run this command each time you connect to a network.
>
> To automate it, see [Auto set route and DNS](#auto-set-route-and-dns).

```shell
# Get IP of dae VM.
dae_ip=$(limactl shell dae ip --json addr | limactl shell dae jq -cr '.[] | select( .ifname == "lima0" ).addr_info | .[] | select( .family == "inet" ).local')
# Set gateway of macOS host to dae VM.
sudo route delete default; sudo route add default $dae_ip
# Set DNS of macOS host to dae VM.
networksetup -setdnsservers Wi-Fi $dae_ip
```

#### 5. Verify connectivity

```shell
# Verify.
curl -v ipinfo.io
```

### Auto set route and DNS

#### 1. Create the network update script

```shell
# The script to execute.
mkdir -p /Users/Shared/bin
cat << 'EOF' > /Users/Shared/bin/dae-network-update.sh
#!/bin/sh
set -ex
export PATH=$PATH:/opt/local/bin/:/opt/homebrew/bin/
dae_ip=$(limactl shell dae ip --json addr | limactl shell dae jq -cr '.[] | select( .ifname == "lima0" ).addr_info | .[] | select( .family == "inet" ).local')
current_gateway=$(route -n get default|grep gateway|rev|cut -d' ' -f1|rev)
networksetup -getdnsservers Wi-Fi | cut -d" " -f1 | grep -E '\.|:' && dns_override=1
[ ! -z "$dae_ip" ] && ping -c 1 -t 1 -n "$dae_ip" && dae_ready=1
[ -z "$dae_ready" ] && [ ! -z "$dns_override" ] && (networksetup -setmanual Wi-Fi 1.1.1.1 255.255.255.255 1.1.1.1; networksetup -setdhcp Wi-Fi; networksetup -setdnsservers Wi-Fi "Empty"; exit 1)
[ "$current_gateway" != "$dae_ip" ] && (sudo route delete default; sudo route add default $dae_ip)
networksetup -setdnsservers Wi-Fi $dae_ip
exit 0
EOF

# Give executable permission.
chmod +x /Users/Shared/bin/dae-network-update.sh
```

#### 2. Allow `route` to run without a password

```shell
if [ $(id -u) -eq "0" ]; then echo 'Do not use root!!'; else echo "$(whoami) ALL=(ALL) NOPASSWD: $(which route)" | sudo tee /etc/sudoers.d/"$(whoami)"-route; fi
```

#### 3. Create the plist service file

```shell
cat << 'EOF' > ~/Library/LaunchAgents/org.v2raya.dae.networkchanging.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.v2raya.dae.networkchanging</string>

  <key>LowPriorityIO</key>
  <true/>

  <key>ProgramArguments</key>
  <array>
    <string>/Users/Shared/bin/dae-network-update.sh</string>
  </array>

  <key>WatchPaths</key>
  <array>
    <string>/etc/resolv.conf</string>
    <string>/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist</string>
    <string>/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist</string>
  </array>

  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
EOF
```

#### 4. Load the plist service

```shell
launchctl load ~/Library/LaunchAgents/org.v2raya.dae.networkchanging.plist
```
