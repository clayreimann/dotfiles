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
# Sets GIT_CONFIG_GLOBAL to agent-specific config so Claude/Codex
# use the local signing key instead of 1Password
claude-agent-sign() {
  GIT_CONFIG_GLOBAL="$HOME/.gitconfig-agent" claude "$@"
}

codex-agent-sign() {
  GIT_CONFIG_GLOBAL="$HOME/.gitconfig-agent" codex "$@"
}
