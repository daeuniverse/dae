set -l __dae_commands export help reload run suspend validate honk

complete -c dae -f

#help version
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -o v -l version -d "version for dae"
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -o h -l help -d "Help for dae"

#dae
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -a export -d "To export some information for UI developers"
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -a reload -d "To reload config file without interrupt connections"
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -a run -d "To run dae in the foreground"
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -a suspend -d "To suspend dae (Recover it by 'dae reload')"
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -a validate -d "To validate dae config"
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -a honk -d "Let dae call for you"
complete -c dae -n "not __fish_seen_subcommand_from $__dae_commands" -a help -d "Help about any command"

#export
complete -c dae -n "__fish_seen_subcommand_from export; and not __fish_seen_argument -a outline" -a "outline" -d "Export config structure"

#reload suspend
complete -c dae -n "__fish_seen_subcommand_from suspend reload" -a "(__fish_complete_pids)"
complete -c dae -n "__fish_seen_subcommand_from suspend reload" -o a -l abort -d "Abort established connections"

#run
complete -c dae -n "__fish_seen_subcommand_from run" -l disable-pidfile -d "Not generate /var/run/dae.pid"
complete -c dae -n "__fish_seen_subcommand_from run" -l disable-timestamp -d "Disable timestamp"
complete -c dae -n "__fish_seen_subcommand_from run" -l logfile-maxbackups -x -d "The maximum number of old log files to retain"
complete -c dae -n "__fish_seen_subcommand_from run" -o c -l config -d "Config file of dae"
complete -c dae -n "__fish_seen_subcommand_from run" -l logfile-maxsize -x -d "Unit: MB. The maximum size of the log file before rotation"
complete -c dae -n "__fish_seen_subcommand_from run" -l logfile -d "Log file to write"
complete -c dae -n "__fish_seen_subcommand_from run; and __fish_seen_argument -s c -l config -l logfile" -F

#validate
complete -c dae -n "__fish_seen_subcommand_from validate" -o c -l config -d "Config file of dae"
complete -c dae -n "__fish_seen_subcommand_from validate; and __fish_seen_argument -s c -l config" -F

#help
complete -c dae -n "__fish_seen_subcommand_from help" -a "export help reload run suspend validate honk"

function __dae_subcommand_help
    set sub $argv[1]
    complete -c dae -xn "__fish_seen_subcommand_from $sub" -o h -l help -d "Help for $sub"
end

for cmd in $__dae_commands
    __dae_subcommand_help $cmd
end
