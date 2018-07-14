#!/usr/bin/env bash
SCM_NONE_CHAR=""
SCM_THEME_PROMPT_DIRTY=" ${red}✗"
SCM_THEME_PROMPT_CLEAN=" ${bold_green}✓"
SCM_THEME_PROMPT_PREFIX="|${cyan}"
SCM_THEME_PROMPT_SUFFIX="${green}| "


function git_prompt_info {
  git_prompt_vars
  echo -e "$SCM_PREFIX$SCM_BRANCH$SCM_STATE$SCM_GIT_AHEAD$SCM_GIT_BEHIND$SCM_GIT_STASH$SCM_SUFFIX"
}

LAST_PROMPT=""
function prompt_command() {
    local new_PS1="${bold_cyan}$(scm_char) ${green}\w $(scm_prompt_info)"
    local new_prompt=$(PS1="$new_PS1" "$BASH" --norc -i </dev/null 2>&1 | sed -n '${s/^\(.*\)exit$/\1/p;}')

    if [ "$LAST_PROMPT" = "$new_prompt" ]; then
        new_PS1=""
    else
        LAST_PROMPT="$new_prompt"
    fi

    local wrap_char=""
    [[ $COLUMNS && $((${#new_PS1} > $COLUMNS/1 )) != 0 ]] && wrap_char="\n"
    PS1="${new_PS1}${wrap_char}${green}→${reset_color} "
}

safe_append_prompt_command prompt_command
