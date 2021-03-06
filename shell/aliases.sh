alias nano="nano --tabstospaces --tabsize=2"

alias atom="atom ."
alias atom_="/usr/local/bin/atom"
alias dotfiles="atom_ ~/dotfiles"
alias hosts="sudo nano /etc/hosts"
alias "show-ssh"="ps -ef | grep ssh | grep -v grep"
alias rotateSshPass="ssh-keygen -p -f ~/.ssh/id_rsa"
alias renewTunnels="ssh corona './corona/server/dev/burst.sh'"
alias reload="source ~/.bash_profile"
alias flash="FORCE_PROMPT=true"

toggle() {
  if [ "$ALWAYS_PROMPT" = "" ]; then
    ALWAYS_PROMPT="true"
  else
    ALWAYS_PROMPT=""
  fi
}
