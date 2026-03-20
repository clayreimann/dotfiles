# Git
alias g='git'
alias gco='git checkout'
alias gcm='git checkout main && git pull'
alias gcmr='git checkout master && git pull'
alias gc='git commit'
alias ga='git add'
alias gca='git add . ; git commit'
alias gcam='git add . ; git commit -m'
alias gst='git status'
alias gup='git push'
alias gsave='git add . && git commit -am "Checkpoint"'
alias gdiff='git diff'
alias reload='source $ZDOTDIR/.zshrc'
alias customize='$EDITOR $ZDOTDIR/.zshrc'
alias profile='for i in $(seq 1 10); do /usr/bin/time zsh -i -c exit; done'

# Kubernetes
alias k='kubectl'
alias kl='kubectl login'
alias kgd='kubectl get deployment'
alias ked='kubectl edit deployment'
alias ksd='kubectl scale deployment'
alias kgss='kubectl get statefulset'
alias ksss='kubectl scale statefulset'

# ls with eza
alias ls='eza --icons'
alias ll='eza -la --icons'
alias lt='eza --tree --icons'

# System / nano
alias nano='nano --tabstospaces --tabsize=2'
alias hosts='sudo nano /etc/hosts'
alias show-ssh='ps -ef | grep ssh | grep -v grep'
