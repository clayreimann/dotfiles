alias nano="nano --tabstospaces --tabsize=2"

alias atom="atom ."
alias atom_="/usr/local/bin/atom"
alias dotfiles="atom_ ~/dotfiles"
alias hosts="sudo nano /etc/hosts"
alias addKey="ssh-add ~/.ssh/id_rsa"
alias rotateSshPass="ssh-keygen -p -f ~/.ssh/id_rsa"
alias renewTunnels="ssh corona './corona/server/dev/burst.sh'"
