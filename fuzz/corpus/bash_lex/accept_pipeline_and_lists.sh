npm test 2>&1 | tail -n 20 && echo ok || echo fail; sleep 1 &
