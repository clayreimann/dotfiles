# Git
gput() { git push -u origin "$(git branch --show-current)" "$@"; }
gpfork() { git push -u clayreimann "$(git branch --show-current)" "$@"; }
gcb() { git checkout -b "$(echo "$@" | sed 's/ /-/g')"; }

# VPN
vpn_remaining() {
  vzmvpn stats | grep "Session Disconnect" | cut -d ' ' -f5-
}

# Kubernetes
kgp() {
  if [ "$1" != '' ]; then
    kubectl get pods | grep "$1"
  else
    kubectl get pods
  fi
}
kexec() {
  local container=''
  if [ "$2" != '' ]; then container="-c='$2'"; fi
  kubectl exec -it "$1" $container -- /bin/bash
}

# Java — mise handles switching: `mise use java@8` or `mise use java@21`
# switch_java is a no-op alias for muscle memory
alias switch_java='echo "Use: mise use java@<version>"'

# Agent commit signing wrappers
# Restore the default machine-local Git identity inherited by non-interactive processes.
claude-agent-sign() {
  GIT_CONFIG_GLOBAL="$HOME/.gitconfig" claude "$@"
}

codex-agent-sign() {
  GIT_CONFIG_GLOBAL="$HOME/.gitconfig" codex "$@"
}

# Launch desktop agent apps with the non-interactive Git signing config.
# Quit an already-running app first: environment variables are fixed at launch.
_agent-app-sign() {
  local app_name="$1"

  if pgrep -x "$app_name" >/dev/null; then
    echo "$app_name is already running. Quit it, then run this command again." >&2
    return 1
  fi

  open -a "$app_name" --env "GIT_CONFIG_GLOBAL=$HOME/.gitconfig"
}

chatgpt-app-agent-sign() {
  _agent-app-sign "ChatGPT"
}

claude-app-agent-sign() {
  _agent-app-sign "Claude"
}
