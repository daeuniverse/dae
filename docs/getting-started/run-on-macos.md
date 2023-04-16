# Run on macOS

## Install brew

### For x86

You can install brew referring to official docs <https://docs.brew.sh/Installation>:

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

### For arm64

To install arm64 architecture packages, homebrew should be installed in `/opt/homebrew`:

```shell
cd /opt
sudo mkdir homebrew
sudo chown $(whoami):admin homebrew
curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip 1 -C homebrew
```

## Lima

This chapter intruduces how to use [lima](https://github.com/lima-vm/lima) virtual machine to run dae.

First, we should install `lima` and `socket_vmnet`.

```shell
# Install socket_vmnet for bridge.
brew install socket_vmnet

# Set up the sudoers file for launching socket_vmnet from Lima
limactl sudoers >etc_sudoers.d_lima
sudo install -o root etc_sudoers.d_lima /etc/sudoers.d/lima
```

Then, configure lima configuration and dae VM configuration.

```shell
# Configure lima networks.
socket_vmnet_bin=$(readlink -f ${HOMEBREW_PREFIX}/opt/socket_vmnet)/bin/socket_vmnet
sed -ir "s#^ *socketVMNet:.*#  socketVMNet: \"${socket_vmnet_bin}\"#" .lima/_config/networks.yaml
```

```shell
# Configure dae vm.
mkdir ~/.lima/dae/
cat << 'EOF' | tee ~/.lima/dae/lima.yaml
images:
- location: "https://cloud.debian.org/images/cloud/bookworm/daily/20230416-1352/debian-12-generic-amd64-daily-20230416-1352.qcow2"
  arch: "x86_64"
  digest: "sha512:8dcb07f213bbe7436744ce310252f53eb06d8d0a85378e4bdeb297e29d7f8b8af82b038519fabca84a75f188aa4e5586d21856d1bb09ab89aca70fd39be7c06b"
- location: "https://cloud.debian.org/images/cloud/bookworm/daily/20230416-1352/debian-12-generic-arm64-daily-20230416-1352.qcow2"
  arch: "aarch64"
  digest: "sha512:88020fbde570e4bc773d6b05d810150b64fea007a2a18dfee835f1d73025bd2872300352e5cb1acb0bb4784c3c6765be1007880177f5319385d4fdf1d75e3ccf"
mounts:
networks:
- lima: bridged
  interface: "lima0"
memory: "1GB"
disk: "20GiB"
EOF
```

Start dae VM and configure it.

```shell
# Start dae VM.
limactl start dae
```

```shell
# Enter the dae VM.
limactl shell dae

# Disable to auto configure network.
echo "network: {config: disabled}" | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

# Manually configure network.
cat << 'EOF' | sudo tee /etc/netplan/50-cloud-init.yaml
network:
    ethernets:
        eth0:
            dhcp4: true
            match:
                macaddress: 52:55:55:83:ed:b2
            set-name: eth0
            dhcp4-overrides:
                use-routes: false
                use-dns: false
        lima0:
            dhcp4: true
            match:
                macaddress: 52:55:55:e6:86:c5
            set-name: lima0
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

# See https://github.com/daeuniverse/dae/blob/main/docs/dns.md for full examples.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google.com:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    request {
      fallback: alidns
    }
    response {
      upstream(googledns) -> accept
      !qname(geosite:cn) && ip(geoip:private) -> googledns
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

# See https://github.com/daeuniverse/dae/blob/main/docs/routing.md for full examples.
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

Set default route of macOS to dae VM.

> **Note**
> You may need to execute this command every time you connect to network.
>
> Refer to [run a script after a interface comes up](https://apple.stackexchange.com/questions/32354/how-do-you-run-a-script-after-a-network-interface-comes-up) if you want to auto execute it.

```shell
# Set gateway of macOS host to dae vm.
sudo route delete default; sudo route add default $(limactl shell dae ip --json addr | limactl shell dae jq -cr '.[] | select( .ifname == "lima0" ).addr_info | .[] | select( .family == "inet" ).local')
```

Verify that we were successful.

```shell
# Verify.
curl -v ipinfo.io
```
