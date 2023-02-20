# Run Dae as a Daemon Service

[systemd](https://wiki.debian.org/systemd) allows you to create and manage services in extremely powerful and flexible ways.

Dae can be running as a daemon(systemd) service so that it can run at boot.

## Setup

```bash
sudo tee /etc/systemd/system/dae.service<<EOF
[Unit]
Description=dae Service
Documentation=https://github.com/v2rayA/dae
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
LimitNPROC=500
LimitNOFILE=1000000
ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae
ExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dae --now
sudo systemctl status dae
```

## Check System Logs

```bash
sudo journalctl -xefu dae
```
