# bash completion for dae                                  -*- shell-script -*-
#
# To be installed in "/usr/share/bash-completion/completions/dae"

_dae() {
	local prev cur cmd export_cmd run_opts trace_opts validate_opts
	COMPREPLY=()

	prev="${COMP_WORDS[COMP_CWORD-1]}"
	cur="${COMP_WORDS[COMP_CWORD]}"
	cmd="export help honk reload run suspend trace validate"
	export_cmd="outline"
	run_opts="-c --config --disable-pidfile --disable-timestamp --logfile \
		--logfile-maxbackups --logfile-maxsize"
	trace_opts="-4 --ipv4 -6 --ipv6 -p --l4-proto -o --output -P \
		--port"
	validate_opts="-c --config"

	case "${prev}" in
		help)
			return 0
			;;

		honk|reload|suspend|outline)
			COMPREPLY=( $(compgen -W "-h --help" -- "${cur}") )
			return 0
			;;
            
		export)
			COMPREPLY=( $(compgen -W "$export_cmd -h --help" -- \
				"${cur}") )
			return 0
			;;
            
		run)
			COMPREPLY=( $(compgen -W "$run_opts -h --help" -- \
				"${cur}") )
			return 0
			;;

		trace)
			COMPREPLY=( $(compgen -W "$trace_opts -h --help" -- \
				"${cur}") )
			return 0
			;;

		validate)
			COMPREPLY=( $(compgen -W "$validate_opts -h --help" -- \
				"${cur}") )
			return 0
			;;

		# multiple option matching
		--disable-pidfile|--disable-timestamp|--logfile|\
			--logfile-maxbackup|--logfile-maxsize|-c|--config)

			case "${prev}" in
				--logfile)
					COMPREPLY=()
					_filedir '@(log)'
					return 0
					;;
			esac

			case "${prev}" in
				-c|--config)
					COMPREPLY=()
					_filedir '@(dae)'
					return 0
					;;
			esac

			case "${COMP_WORDS[1]}" in
				run)
					COMPREPLY=( $(compgen -W "$run_opts" -- \
						"${cur}") )
					return 0
					;;
			esac

			return 0
			;;

		-h|--help)
			return 0
			;;

		*)
			;;
	esac

	case "${cur}" in
		-*)
			COMPREPLY=( $( compgen -W "--version --help -v -h" -- \
				"${cur}") )
			return 0
			;;
		--*)
			COMPREPLY=( $( compgen -W "--version --help" -- \
				"${cur}") )
			return 0
			;;
		*)
			case "${COMP_WORDS[1]}" in
				export|help|honk|reload|run|suspend|validate)
					return 0
					;;
			esac

			COMPREPLY=( $( compgen -W "${cmd}" -- "${cur}") )
			return 0
			;;
	
	esac

}

complete -F _dae dae
