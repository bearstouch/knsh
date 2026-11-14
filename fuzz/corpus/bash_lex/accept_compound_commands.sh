if [[ -f x ]]; then { a; b; }; fi; for i in 1 2; do (cd $i && make); done; f() { :; }
