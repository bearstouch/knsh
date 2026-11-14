bash <<EOF
rm -rf $(pwd)/build
EOF
cat <<-'X' 3<<<"$(date)"
	$(not run)
	X
python3 <<< "print(1)"
