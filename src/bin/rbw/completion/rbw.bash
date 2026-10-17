_rbw_wrapper() {
  local cur prev folder attachment opts res name user start mode acct send_subcmd
  COMPREPLY=()

  for (( i=1; i < ${#COMP_WORDS[@]}; i++ )); do
    case "${COMP_WORDS[i-1]}" in
      -a|--account) acct="${COMP_WORDS[i]}" ;;
    esac
    case "${COMP_WORDS[i]}" in
      --account=*) acct="${COMP_WORDS[i]#--account=}" ;;
    esac
  done

  # --collection/--org take a collection/org name, regardless of which
  # subcommand they're used on (get/show/code/edit/set/rm/archive/
  # unarchive/restore/history/list/search all accept them) -- so this is
  # checked unconditionally, ahead of the get/attachment-specific dynamic
  # completion below, which only ever covers those two commands.
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  # `rbw mirror --from A --to B ...`: --collection/--org-id scope the
  # source (account A), --dest-collection/--dest-org scope the
  # destination (account B) -- so these complete against whichever
  # account was already typed for --from/--to, not the default account
  # the generic case below would use. --org-id takes a raw ID (not
  # resolved by name anywhere), so it's left uncompleted.
  if [[ "${COMP_WORDS[1]}" == "mirror" ]]; then
    local from_acct="" to_acct=""
    for (( i=2; i < ${#COMP_WORDS[@]}; i++ )); do
      case "${COMP_WORDS[i]}" in
        --from) from_acct="${COMP_WORDS[i+1]}" ;;
        --to) to_acct="${COMP_WORDS[i+1]}" ;;
      esac
    done

    case "$prev" in
      --from|--to)
        res=$(rbw account list 2>/dev/null | cut -f1 | sed 's/\*$//')
        mapfile -t opts <<< "$res"
        COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
        return 0
        ;;
      --collection)
        [[ -n "$from_acct" ]] && res=$(rbw --account "$from_acct" collection list --output name 2>/dev/null)
        mapfile -t opts <<< "$res"
        COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
        return 0
        ;;
      --dest-collection)
        [[ -n "$to_acct" ]] && res=$(rbw --account "$to_acct" collection list --output name 2>/dev/null)
        mapfile -t opts <<< "$res"
        COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
        return 0
        ;;
      --dest-org)
        [[ -n "$to_acct" ]] && res=$(rbw --account "$to_acct" org list --output name 2>/dev/null)
        mapfile -t opts <<< "$res"
        COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
        return 0
        ;;
    esac

    _rbw "$@"
    return
  fi

  local prev_flag="$prev"
  if [[ "$prev" == "=" && $COMP_CWORD -ge 2 ]]; then
    prev_flag="${COMP_WORDS[COMP_CWORD-2]}"
  fi

  case "$prev_flag" in
    -a|--account)
      res=$(rbw account list 2>/dev/null | cut -f1 | sed 's/\*$//')
      mapfile -t opts <<< "$res"
      COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
      return 0
      ;;
    -o|--output)
      opts=(name json yaml)
      COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
      return 0
      ;;
    --name|-t|--text|-n|--notes|-p|--password|-d|--days|--deletion-date|--expire-in|--expiration-date|-m|--max-access-count)
      return 0
      ;;
    --collection)
      res=$(rbw ${acct:+--account=$acct} collection list --output name 2>/dev/null)
      mapfile -t opts <<< "$res"
      COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
      return 0
      ;;
    --org)
      res=$(rbw ${acct:+--account=$acct} org list --output name 2>/dev/null)
      mapfile -t opts <<< "$res"
      COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
      return 0
      ;;
  esac

  if [[ "${COMP_WORDS[1]}" == "get" ]]; then
    start=2
    mode=get
  elif [[ "${COMP_WORDS[1]}" == "attachment" ]] \
    && [[ "${COMP_WORDS[2]}" == "get" || "${COMP_WORDS[2]}" == "list" || "${COMP_WORDS[2]}" == "rm" ]]; then
    start=3
    mode=attachment
  fi

  if [[ -z "$mode" ]]; then
    for (( i=1; i < COMP_CWORD; i++ )); do
      if [[ "${COMP_WORDS[i]}" == "send" ]]; then
        for (( j=i+1; j < COMP_CWORD; j++ )); do
          case "${COMP_WORDS[j]}" in
            -a|--account)
              (( j++ ))
              if [ "${COMP_WORDS[j]}" == "=" ]; then (( j++ )); fi
              ;;
            --account=*)
              ;;
            -*)
              ;;
            view|get|show|edit|update|remove|rm|delete|link|url)
              start=$((j + 1))
              mode=send
              send_subcmd="${COMP_WORDS[j]}"
              break 2
              ;;
            *)
              break
              ;;
          esac
        done
      fi
    done
  fi

  if [[ -n "$mode" ]] && [[ $COMP_CWORD -ge $start ]]; then
    for (( i=start; i < COMP_CWORD; i++ )); do
      case "${COMP_WORDS[i]}" in
        --folder|--attachment|-f|--field)
          (( i++ ))
          if [ "${COMP_WORDS[i]}" == "=" ]; then
            (( i++ ))
          fi
          ;;
        --name|-t|--text|-n|--notes|-p|--password|-d|--days|--deletion-date|--expire-in|--expiration-date|-m|--max-access-count|-o|--output)
          (( i++ ))
          if [ "${COMP_WORDS[i]}" == "=" ]; then
            (( i++ ))
          fi
          ;;
        -*)
          ;;
        *)
          if [ -z "$name" ]; then
            name="${COMP_WORDS[i]}"
          elif [[ "$mode" == get ]]; then
            user="${COMP_WORDS[i]}"
            break
          fi
          ;;
      esac
    done

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    for (( i=start; i < ${#COMP_WORDS[@]}; i++ )); do
      if [[ "${COMP_WORDS[i-2]}" == "--folder" ]] && [[ "${COMP_WORDS[i-1]}" == "=" ]]; then
        folder="${COMP_WORDS[i]}"
        if [[ $i -eq $COMP_CWORD ]]; then
          prev="--folder"
        fi
      elif [[ "${COMP_WORDS[i-1]}" == "--folder" ]] && [[ "${COMP_WORDS[i]}" == "=" ]]; then
        folder=""
        if [[ $i -eq $COMP_CWORD ]]; then
          prev="--folder"
          cur=""
        fi
      elif [[ "${COMP_WORDS[i-1]}" == "--folder" ]]; then
        folder="${COMP_WORDS[i]}"
      fi

      if [[ "${COMP_WORDS[i-2]}" == "--attachment" ]] && [[ "${COMP_WORDS[i-1]}" == "=" ]]; then
        attachment="${COMP_WORDS[i]}"
        if [[ $i -eq $COMP_CWORD ]]; then
          prev="--attachment"
        fi
      elif [[ "${COMP_WORDS[i-1]}" == "--attachment" ]] && [[ "${COMP_WORDS[i]}" == "=" ]]; then
        attachment=""
        if [[ $i -eq $COMP_CWORD ]]; then
          prev="--attachment"
          cur=""
        fi
      elif [[ "${COMP_WORDS[i-1]}" == "--attachment" ]]; then
        attachment="${COMP_WORDS[i]}"
      fi
    done

    if [[ "$prev" == --folder ]]; then
      # rbw get --folder $folder
      res=$(
        rbw list --fields folder 2>/dev/null \
          | awk -v folder="$folder" 'NF && $1 ~ folder && !a[$1]++ {print $1}' 2>/dev/null
      )
    elif [[ "$mode" == attachment ]] && [[ "$prev" == --attachment ]]; then
      # rbw attachment get $name --attachment $cur
      res=$(
        rbw attachment list "$name" --output name 2>/dev/null
      )
    elif [[ "$prev" != --field ]]; then
      if [ -z "$name" ]; then
        # rbw get ... $cur
        if [[ "$mode" == attachment ]]; then
          res=$(
            rbw ${acct:+--account=$acct} list --fields name,folder --with-attachments 2>/dev/null \
              | awk -F'\t' -v folder="$folder" '$1 && (!folder || $2 == folder) {print $1}' 2>/dev/null
          )
        elif [[ "$mode" == send ]]; then
          res=$(rbw ${acct:+--account=$acct} send list --output name 2>/dev/null)
        else
          res=$(
            rbw ${acct:+--account=$acct} list --fields name,folder 2>/dev/null \
              | awk -F'\t' -v folder="$folder" '$1 && (!folder || $2 == folder) {print $1}' 2>/dev/null
          )
        fi
      elif [[ "$mode" == get ]] && [ -z "$user" ]; then
        # rbw get ... name $cur
        res=$(
          rbw ${acct:+--account=$acct} list --fields name,folder,user 2>/dev/null \
            | awk -F'\t' -v name="$name" -v folder="$folder" '$1 == name && (!folder || $2 == folder) {print $3}' 2>/dev/null
        )
      fi
    else
      _rbw "$@"
      return
    fi

    if [[ "$cur" == -* ]]; then
      if [[ "$mode" == attachment ]]; then
        case "${COMP_WORDS[2]}" in
          get)
            res="-o --output --raw -h --help $res"
            [ -z "$attachment" ] && res="--attachment $res"
            ;;
          list)
            res="-o --output -j --raw --json --yaml -h --help $res"
            ;;
          rm)
            res="-y --yes -h --help $res"
            [ -z "$attachment" ] && res="--attachment $res"
            ;;
        esac
        res="--user --collection --org -i --ignorecase -e --exact $res"
      elif [[ "$mode" == send ]]; then
        case "$send_subcmd" in
          view|get|show)
            res="-t --text -o --output -j --raw --json --yaml -a --account -h --help $res"
            ;;
          edit|update)
            res="--name -t --text -n --notes -p --password --remove-password --hidden --visible --disable --enable --hide-email --show-email -d --days --deletion-date --expire-in --expiration-date --clear-expiration -m --max-access-count --clear-max-access -a --account -h --help $res"
            ;;
          remove|rm|delete)
            res="-y --yes -a --account -h --help $res"
            ;;
          link|url)
            res="-c --copy -a --account -h --help $res"
            ;;
        esac
      else
        res="-f --field --full --raw --clipboard --collection --org -i --ignorecase --all -h --help $res"
        if [ -z "$folder" ]; then
          res="--folder $res"
        fi
      fi
    fi

    mapfile -t opts <<< "$res"
    COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
    return 0
  else
    _rbw "$@"
  fi
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _rbw_wrapper -o nosort -o bashdefault -o default rbw
else
    complete -F _rbw_wrapper -o bashdefault -o default rbw
fi
