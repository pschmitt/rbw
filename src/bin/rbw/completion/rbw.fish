function __fish_rbw_get_completion_name
    set -l cmd (commandline -xpc)
    set -e cmd[1] # rbw

    argparse -i folder= f/field= full raw clipboard i/ignorecase h/help l/list-fields all -- $cmd
    set -e argv[1] # get

    set -l candidates (command rbw list --fields name,folder,user)
    # if folder is set, filter by it
    if set -q _flag_folder
        set candidates (printf '%s\n' $candidates | string match -er "^[^\t]*\t$_flag_folder\t")
    end

    switch (count $argv)
        case 0
            # print completion for NAME argument in the format of
            # NAME   (USERNAME [FOLDER])
            printf '%s\n' $candidates | while read -l line
                set --local parts (string split \t $line)

                set --local _name $parts[1]
                set --local _folder $parts[2]
                set --local _user $parts[3]

                if test -n "$_folder"
                    printf '%s\t%s [%s]\n' $_name $_user $_folder
                else
                    printf '%s\t%s\n' $_name $_user
                end
            end
        case 1
            # filter by NAME
            set candidates (printf '%s\n' $candidates | string match -er "^$argv[1]\t")
            # print completion for USER argument in the format of
            # USER   ([FOLDER])
            printf '%s\n' $candidates | while read -l line
                set --local parts (string split \t $line)

                set --local _user $parts[3]
                if test "$_user" != ""
                    # non-empty
                    set --local _folder $parts[2]
                    if test -n "$_folder"
                        printf '%s\t[%s]\n' $_user $_folder
                    else
                        printf '%s\n' $_user
                    end
                end
            end
    end
end

function __fish_rbw_get_completion_fields
    set -l cmd (commandline -xpc)
    set -e cmd[1] # rbw
    if test -z "$(commandline -xpt)"
        set -e cmd[-1] # -f/--field
    end

    argparse -i folder= f/field= full raw clipboard i/ignorecase h/help l/list-fields all -- $cmd
    set -e argv[1] # get

    if test (count $argv) -gt 0
        command rbw get "$argv[1]" --list-fields 2>/dev/null
    end
end

complete -f -c rbw -n '__fish_seen_subcommand_from get edit' -a '(__fish_rbw_get_completion_name)'

# Complete options for `rbw get`
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s i -l ignorecase -d 'Ignore case'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s f -l field -r -d 'Field to get' -a '(__fish_rbw_get_completion_fields)'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s l -l list-fields -r -d 'List fields in this entry'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -l folder -r -d 'Folder name to search in' -a '(command rbw list --fields folder)'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -l full -d 'Display the notes in addition to the password'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -l raw -d 'Display output as JSON'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s c -l clipboard -d 'Copy result to clipboard'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -l all -d 'Search every unlocked account, not just the primary'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s h -l help -d 'Print help'

# `rbw attachment {get,list,rm}` completions: entry name, and the
# --attachment id/filename, both resolved live against the vault since
# clap can't know either of them ahead of time.
function __fish_rbw_attachment_using_subcommand
    __fish_seen_subcommand_from attachment
    and __fish_seen_subcommand_from $argv
end

function __fish_rbw_attachment_completion_name
    set -l cmd (commandline -xpc)
    set -e cmd[1] # rbw
    set -e cmd[1] # attachment
    set -e cmd[1] # get/list/ls/rm/remove/delete

    argparse -i folder= user= i/ignorecase e/exact attachment= o/output= j/raw yaml y/yes h/help -- $cmd

    set -l candidates (command rbw list --fields name,folder --with-attachments)
    if set -q _flag_folder
        set candidates (printf '%s\n' $candidates | string match -er "^[^\t]*\t$_flag_folder\t")
    end

    printf '%s\n' $candidates | while read -l line
        set --local parts (string split \t $line)

        set --local _name $parts[1]
        set --local _folder $parts[2]
        if test -n "$_folder"
            printf '%s\t[%s]\n' $_name $_folder
        else
            printf '%s\n' $_name
        end
    end
end

function __fish_rbw_attachment_completion_attachment
    set -l cmd (commandline -xpc)
    set -e cmd[1] # rbw
    set -e cmd[1] # attachment
    set -e cmd[1] # get/rm
    if test -z "$(commandline -xpt)"
        set -e cmd[-1] # --attachment
    end

    argparse -i folder= user= i/ignorecase e/exact attachment= o/output= j/raw yaml y/yes h/help -- $cmd

    if test (count $argv) -gt 0
        command rbw attachment list "$argv[1]" --output name 2>/dev/null
    end
end

complete -f -c rbw -n '__fish_rbw_attachment_using_subcommand get list ls rm remove delete' -a '(__fish_rbw_attachment_completion_name)'
complete -f -c rbw -n '__fish_rbw_attachment_using_subcommand get' -l attachment -a '(__fish_rbw_attachment_completion_attachment)'
complete -f -c rbw -n '__fish_rbw_attachment_using_subcommand rm remove delete' -l attachment -a '(__fish_rbw_attachment_completion_attachment)'
