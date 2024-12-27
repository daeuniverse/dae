#!/bin/bash

if [ $(command -v systemctl) ]; then
	systemctl daemon-reload

	if [ $(systemctl is-active dae) ]; then
		systemctl restart dae.service
		echo "Restarting dae service, it might take a while."
	fi
fi
