# Persistent and automatically update subscriptions

[systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html) allows you to run a service periodically.

The current behavior of dae is to pull subscriptions at startup, but this can sometimes result in an empty group if there is a network anomaly or other possible reason when pulling subscriptions.

We'll introduce a way to achieve persistent subscription storage and automatic subscription updates through the systemd service and timer.

## Preparations

### Shell script

We assume that your dae configuration file is stored in `/usr/local/etc/dae/` .

`/usr/local/bin/update-dae-subs.sh`:

```sh
#!/bin/bash

# Change the path to suit your needs
cd /usr/local/etc/dae || exit 1
version="$(dae --version | head -n 1 | sed 's/dae version //')"
UA="dae/${version} (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)"
fail=false

while IFS=':' read -r name url
do
        curl --retry 3 --retry-delay 5 -fL -A "$UA" "$url" -o "${name}.sub.new"
        if [[ $? -eq 0 ]]; then
                mv "${name}.sub.new" "${name}.sub"
                chmod 0600 "${name}.sub"
                echo "Downloaded $name"
        else
                if [ -f "${name}.sub.new" ]; then
                        rm "${name}.sub.new"
                fi
                fail=true
                echo "Failed to download $name"
        fi
done < sublist

dae reload

if $fail; then
        echo "Failed to update some subs"
        exit 2
fi
```

You need to give it proper permission:

```sh
chmod +x /usr/local/bin/update-dae-subs.sh
```

### `systemd.timer` and `systemd.service`

This timer will automatically update dae subscriptions every 12 hours, or 15 minutes after each boot.

`/etc/systemd/system/update-subs.timer`:

```systemd
[Unit]
Description=Auto-update dae subscriptions

[Timer]
OnBootSec=15min
OnUnitActiveSec=12h

[Install]
WantedBy=timers.target
```

`/etc/systemd/system/update-subs.service`:

```systemd
[Unit]
Description=Update dae subscriptions
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-dae-subs.sh
Restart=on-failure
```

## Configurations

Put your subscription links into `/usr/local/etc/dae/sublist`:

```text
sub1:https://mysub1.com
sub2:https://mysub2.com
sub3:https://mysub3.com
```

Give the file appropriate permissions (for your privacy):

```sh
chmod 0600 /usr/local/etc/dae/sublist
```

Edit `config.dae`:

```text
subscription {
    # Add your subscription links here.
    sub1:'file://sub1.sub'
    sub2:'file://sub2.sub'
    sub3:'file://sub3.sub'
}
```

## Enable timer

Execute the following command:

```sh
systemctl enable --now update-dae-subs.timer

# If you need to renew your subscription immediately or haven't pulled a subscription before
systemctl start update-dae-subs.service
```
