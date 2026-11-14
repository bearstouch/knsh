{ rm() { :; }; } >/nonexistent/x; rm -rf x
while break; rm() { :; }; do b; done; rm -rf x
{ echo $((1/0)); rm() { :; }; }
rm -rf x
f() { a; }; case x in x) f() { b; } ;& y) f ;; esac
rm() { :; }; rm() [[ x ]]; rm -rf x
