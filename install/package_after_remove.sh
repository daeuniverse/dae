#!/bin/bash

if [ $(command -v systemctl) ]; then
	systemctl daemon-reload
fi
