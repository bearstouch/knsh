x=$(case $1 in a|b) echo ab;; (c) echo c;; esac) && echo "$x"
