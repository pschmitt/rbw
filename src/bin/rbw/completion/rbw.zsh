_rbw_wrapper() {
  local -a opts
  local cur prev folder attachment res name user start mode

  # --collection/--org take a collection/org name, regardless of which
  # subcommand they're used on -- checked unconditionally, ahead of the
  # get/attachment-specific dynamic completion below, which only ever
  # covers those two commands.
  cur="${words[CURRENT]}"
  prev="${words[CURRENT-1]}"

  # `rbw mirror --from A --to B ...`: --collection/--org-id scope the
  # source (account A), --dest-collection/--dest-org scope the
  # destination (account B) -- so these complete against whichever
  # account was already typed for --from/--to, not the default account
  # the generic case below would use. --org-id takes a raw ID (not
  # resolved by name anywhere), so it's left uncompleted.
  if [[ "${(Q)words[2]}" == "mirror" ]]; then
    local from_acct="" to_acct=""
    for (( i=3; i <= ${#words}; i++ )); do
      case "${(Q)words[i-1]}" in
        --from) from_acct="${(Q)words[i]}" ;;
        --to) to_acct="${(Q)words[i]}" ;;
      esac
    done

    case "$prev" in
      --from|--to)
        res=$(rbw account list 2>/dev/null | cut -f1 | sed 's/ \*$//')
        opts=("${(@f)${res}}")
        compadd -- "${opts[@]}"
        return 0
        ;;
      --collection)
        [[ -n "$from_acct" ]] && res=$(rbw --account "$from_acct" collection list --output name 2>/dev/null)
        opts=("${(@f)${res}}")
        compadd -- "${opts[@]}"
        return 0
        ;;
      --dest-collection)
        [[ -n "$to_acct" ]] && res=$(rbw --account "$to_acct" collection list --output name 2>/dev/null)
        opts=("${(@f)${res}}")
        compadd -- "${opts[@]}"
        return 0
        ;;
      --dest-org)
        [[ -n "$to_acct" ]] && res=$(rbw --account "$to_acct" org list --output name 2>/dev/null)
        opts=("${(@f)${res}}")
        compadd -- "${opts[@]}"
        return 0
        ;;
    esac

    _rbw
    return
  fi

  case "$prev" in
    --collection)
      res=$(rbw collection list --output name 2>/dev/null)
      opts=("${(@f)${res}}")
      compadd -- "${opts[@]}"
      return 0
      ;;
    --org)
      res=$(rbw org list --output name 2>/dev/null)
      opts=("${(@f)${res}}")
      compadd -- "${opts[@]}"
      return 0
      ;;
  esac

  if [[ "${(Q)words[2]}" == "get" ]]; then
    start=3
    mode=get
  elif [[ "${(Q)words[2]}" == "attachment" ]] \
    && [[ "${(Q)words[3]}" == "get" || "${(Q)words[3]}" == "list" || "${(Q)words[3]}" == "rm" ]]; then
    start=4
    mode=attachment
  fi

  if [[ -n "$mode" ]] && [[ $CURRENT -ge $start ]]; then
    for (( i=start; i < CURRENT; i++ )); do
      cur="${(Q)words[i]}"

      case "$cur" in
        --folder|--attachment|-f|--field)
          (( i++ ))
          ;;
        -*)
          ;;
        *)
          if [ -z "$name" ]; then
            name="$cur"
          elif [[ "$mode" == get ]]; then
            user="$cur"
            break
          fi
          ;;
      esac
    done

    cur="${words[CURRENT]}"
    prev="${words[CURRENT-1]}"

    for (( i=start; i <= ${#words}; i++ )); do
      if [[ "${(Q)words[i-1]}" == "--folder" ]]; then
        folder="${(Q)words[i]}"
      elif [[ "${(Q)words[i]}" == "--folder="* ]]; then
        folder="${(Q)words[i]#--folder=}"
      fi

      if [[ "${(Q)words[i-1]}" == "--attachment" ]]; then
        attachment="${(Q)words[i]}"
      elif [[ "${(Q)words[i]}" == "--attachment="* ]]; then
        attachment="${(Q)words[i]#--attachment=}"
      fi
    done

    if [[ "$prev" == "--folder" ]] || [[ "$cur" == "--folder="* ]]; then
      # rbw get --folder $folder
      res=$(
        rbw list --fields folder 2>/dev/null \
          | awk -v folder="$folder" 'NF && $1 ~ folder {print $1}' 2>/dev/null
      )
    elif [[ "$mode" == attachment ]] && ([[ "$prev" == "--attachment" ]] || [[ "$cur" == "--attachment="* ]]); then
      # rbw attachment get $name --attachment $cur
      res=$(
        rbw attachment list "$name" --output name 2>/dev/null
      )
    elif [[ "$prev" != --field ]]; then
      if [ -z "$name" ]; then
        # rbw get ... $cur
        if [[ "$mode" == attachment ]]; then
          res=$(
            rbw list --fields name,folder --with-attachments 2>/dev/null \
              | awk -F'\t' -v folder="$folder" '$1 && (!folder || $2 == folder) {print $1}' 2>/dev/null
          )
        else
          res=$(
            rbw list --fields name,folder 2>/dev/null \
              | awk -F'\t' -v folder="$folder" '$1 && (!folder || $2 == folder) {print $1}' 2>/dev/null
          )
        fi
      elif [[ "$mode" == get ]] && [ -z "$user" ]; then
        # rbw get ... name $cur
        res=$(
          rbw list --fields name,folder,user 2>/dev/null \
            | awk -F'\t' -v name="$name" -v folder="$folder" '$1 == name && (!folder || $2 == folder) {print $3}' 2>/dev/null
        )
      fi
    else
      _rbw
      return
    fi

    if [[ "$cur" == -* ]] && [[ "$cur" != "--folder="* ]] && [[ "$cur" != "--attachment="* ]]; then
      if [[ "$mode" == attachment ]]; then
        case "${(Q)words[3]}" in
          get)
            res=$'-o\n--output\n--raw\n-h\n--help\n'"$res"
            [ -z "$attachment" ] && res=$'--attachment\n'"$res"
            ;;
          list)
            res=$'-o\n--output\n-j\n--raw\n--json\n--yaml\n-h\n--help\n'"$res"
            ;;
          rm)
            res=$'-y\n--yes\n-h\n--help\n'"$res"
            [ -z "$attachment" ] && res=$'--attachment\n'"$res"
            ;;
        esac
        res=$'--user\n--collection\n--org\n-i\n--ignorecase\n-e\n--exact\n'"$res"
      else
        res=$'-f\n--field\n--full\n--raw\n--clipboard\n--collection\n--org\n-i\n--ignorecase\n--all\n-h\n--help\n'"$res"
      fi
      if [ -z "$folder" ]; then
        res=$'--folder\n'"$res"
      fi
    fi

    opts=("${(@f)${res}}")
    # Case-insensitive substring matching so e.g. `rbw get micro<TAB>`
    # completes to `Microsoft (WIIT)` even though the entry name does not
    # start with the typed text (and regardless of the user's matcher-list).
    local -a matcher=(-M 'm:{[:lower:][:upper:]}={[:upper:][:lower:]} l:|=* r:|=*')
    if [[ "$cur" == "--folder="* ]]; then
      compadd "${matcher[@]}" -P '--folder=' -- "${opts[@]}"
    elif [[ "$cur" == "--attachment="* ]]; then
      compadd "${matcher[@]}" -P '--attachment=' -- "${opts[@]}"
    else
      compadd "${matcher[@]}" -- "${opts[@]}"
    fi
  else
    _rbw
  fi
}

compdef _rbw_wrapper rbw
