#compdef _dae dae

_dae() {
	local line

	_arguments -C \
		"-h[help for dae]" \
		"--help[help for dae]" \
		"-v[version for dae]" \
		"--version[version for dae]" \
		"1: :(export help honk reload run suspend validate)" \
		"*::arg:->args"

	case $line[1] in
	export)
		_dae_export
		;;
	help)
		_dae_help
		;;
	honk)
		_dae_honk
		;;
	reload)
		_dae_reload
		;;
	run)
		_dae_run
		;;
	suspend)
		_dae_suspend
		;;
	validate)
		_dae_validate
		;;
	esac

}

_dae_export() {
	_arguments -C \
		"-h[help for export]" \
		"--help[help for export]" \
		"1: :(outline)"
}

_dae_help() {
	_arguments -C \
		"-h[help for help]" \
		"--help[help for help]" \
		"1: :(export help honk reload run suspend validate)"
}

_dae_honk() {
	_arguments -C \
		"-h[help for honk]" \
		"--help[help for honk]"
}

_dae_reload() {
	_arguments -C \
		"-h[help for reload]" \
		"--help[help for reload]" \
		"::pid:($(ps -A | awk '{print $1}'))"
}

_dae_suspend() {
	_arguments -C \
		"-h[help for suspend]" \
		"--help[help for suspend]" \
		"::pid:($(ps -A | awk '{print $1}'))"
}

_dae_run() {
	_arguments -C \
		"-c[Config file of dae]:filename:_files" \
		"--config[Config file of dae]:filename:_files" \
		"--disable-pidfile[Not generate /var/run/dae.pid]" \
		"--disable-timestamp[Disable timestamp]" \
		"--logfile[Log file to write]:filename:_files" \
		"--logfile-maxbackups[The maximum number of old log files to retain]" \
		"--logfile-maxsize[The maximum size in megabytes of the log file before it gets rotated]" \
		"-h[help for run]" \
		"--help[help for run]"
}

_dae_validate() {
	_arguments -C \
		"-c[Config file of dae]:filename:_files" \
		"--config[Config file of dae]:filename:_files" \
		"-h[help for validate]" \
		"--help[help for validate]"
}
