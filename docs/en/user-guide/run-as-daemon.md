# Run dae as a Daemon Service

Run dae as a [systemd](https://wiki.debian.org/systemd) service to start it at boot.
This requires a distribution that uses systemd as its service manager.

## Prerequisites

### Optional Geo Data Files

For traffic splitting, dae uses [geoip.dat](https://github.com/v2fly/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

### Configuration File

Download the sample configuration to the recommended directory, `/etc/dae`:

```bash
mkdir -p /etc/dae
curl -L -o /etc/dae/config.dae https://github.com/daeuniverse/dae/raw/main/example.dae
chmod 600 /etc/dae/config.dae
```

## Download Precompiled Binaries

[Release binaries](https://github.com/daeuniverse/dae/releases) and
[nightly builds](https://github.com/daeuniverse/dae/actions/workflows/build-nightly.yml) are available.

Nightly builds let you try new features. Proposed changes are usually submitted
in PRs and built into cross-platform binaries by GitHub Actions. New features
may contain bugs, so use these builds at your own risk. Testing them helps
assess feature stability and identify bugs.

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

## Memory and Transparent Huge Pages

`GOMEMLIMIT` defaults to 90% of the process's cgroup memory ceiling.
Only `memory.max` determines this ceiling. The bundled unit no longer sets
`MemoryHigh`, which the runtime cannot use as a bound.
An explicit `GOMEMLIMIT` environment variable always takes precedence.

When transparent huge pages are set to `always`, the kernel can increase
dae's resident set without growth in the live Go heap. On every start, reload
and rollback, dae calls `prctl(PR_SET_THP_DISABLE)` for its own process with
the current `disable_thp` value. `true` passes 1 and opts the process out.
The default, `false`, passes 0 and clears any per-process opt-out, including
one inherited from the parent process, so dae follows the system-wide THP
setting. Neither value changes `/sys/kernel/mm/transparent_hugepage`:

```shell
global {
  disable_thp: true
}
```

## Check System Logs

```bash
sudo journalctl -xefu dae
```
