# Run dae as a Daemon Service

[systemd](https://wiki.debian.org/systemd) allows you to create and manage services in extremely powerful and flexible ways.

> **Note**: (Prerequisites) If your distribution's service manager is provided by systemd.

dae can run as a daemon (systemd) service so that it can run at boot.

## Prerequisites

### Optional Geo Data Files

For more convenient traffic split, dae relies on the following data sources, [geoip.dat](https://github.com/v2ray/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2ray/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2ray/domain-list-community/releases/latest/download/dlc.dat
popd
```

### Configuration File

> **Note**: The config file is recommended to save under `/etc/dae`

Download the sample config file:

```bash
mkdir -p /etc/dae
curl -L -o /etc/dae/config.dae https://github.com/daeuniverse/dae/raw/main/example.dae
```

## Download pre-compiled binaries

Releases are available in <https://github.com/daeuniverse/daed/releases>

> **Note**: If you would like to get a taste of new features, there are nightly (latest) builds available. Most of the time, newly proposed changes will be included in `PRs` and will be exported as cross-platform executable binaries in builds (GitHub Action Workflow Build). Noted that newly introduced features are sometimes buggy, so do it at your own risk. However, we still highly encourage you to check out our latest builds as it may help us further analyze features stability and resolve potential bugs accordingly.

Nightly builds are available in <https://github.com/daeuniverse/dae/actions/workflows/build-nightly.yml>

```bash
sudo chmod +x ./dae
sudo install -Dm755 dae /usr/bin/

# helper
dae [-h,--help]
# check version
dae version
```

## Setup

```bash
# download the sample systemd.service
sudo curl -L -o /etc/systemd/system/dae.service https://github.com/daeuniverse/dae/raw/main/install/dae.service

# reload and restart daemon to take effect
sudo systemctl daemon-reload
sudo systemctl enable dae --now
sudo systemctl status dae
```

## Check System Logs

```bash
sudo journalctl -xefu dae
```
