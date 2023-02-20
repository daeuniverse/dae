# Run Dae as a Daemon Service

[systemd](https://wiki.debian.org/systemd) allows you to create and manage services in extremely powerful and flexible ways.

Dae can be running as a daemon(systemd) service so that it can run at boot.

## Setup

```bash
# download the sample systemd.service
sudo curl -L -o /etc/systemd/system/dae.service https://github.com/v2rayA/dae/raw/main/install/dae.service

# reload and restart daemon to take effect
sudo systemctl daemon-reload
sudo systemctl enable dae --now
sudo systemctl status dae
```

## Check System Logs

```bash
sudo journalctl -xefu dae
```
