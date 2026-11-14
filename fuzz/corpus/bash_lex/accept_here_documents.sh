cat <<A <<-"B" >out
user $(id -un) `hostname` \$HOME "q"
A
	literal $(rm -rf /)
	B
echo after
