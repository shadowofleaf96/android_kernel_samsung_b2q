#!/usr/bin/env bash
set -e

# only run if file doesnt already exist
[[ ! -f "binaries/__hosts_k_zip.i" ]] || exit 0

# remove old hosts files
rm -f binaries/__hosts_*

# fetch latest AdAway hosts
curl -k -L -s 'https://adaway.org/hosts.txt' \
	| grep -v '#' \
	| grep -v 'localhost' \
	| sed 's/127.0.0.1/0.0.0.0/g' \
	| grep '0.0.0.0' \
	| grep '.' \
	> binaries/__hosts_k.tmp

# fetch latest StevenBlack hosts
curl -k -L -s 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' \
	| grep -v '#' \
        | grep -v 'localhost' \
	| sed 's/127.0.0.1/0.0.0.0/g' \
	| grep '0.0.0.0' \
	| grep '.' \
	>> binaries/__hosts_k.tmp

# fetch latest winhelp2002 hosts
curl -k -L -s 'https://winhelp2002.mvps.org/hosts.txt' \
        | grep -v '#' \
        | grep -v 'localhost' \
        | sed 's/127.0.0.1/0.0.0.0/g' \
        | grep '0.0.0.0' \
        | grep '.' \
        >> binaries/__hosts_k.tmp

# fetch latest yoyo hosts
curl -k -L -s 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext' \
	| grep -v '#' \
	| grep -v 'localhost' \
	| sed 's/127.0.0.1/0.0.0.0/g' \
	| grep '0.0.0.0' \
	| grep '.' \
	>> binaries/__hosts_k.tmp

# generate [o] original hosts file
echo "127.0.0.1 localhost" > binaries/__hosts_o
echo "::1 ip6-localhost" >> binaries/__hosts_o

# combine [k] kadaway hosts file and remove any duplicates
echo "127.0.0.1 localhost" > binaries/__hosts_k
echo "::1 ip6-localhost" >> binaries/__hosts_k
sort -u binaries/__hosts_k.tmp >> binaries/__hosts_k

# zip hosts_* files
zip -9 -j -q binaries/__hosts_k.zip binaries/__hosts_k
zip -9 -j -q binaries/__hosts_o.zip binaries/__hosts_o

# compile bin2hex binary
gcc binaries/bin2hex.c -o binaries/bin2hex

# encode hosts_* to hex
./binaries/bin2hex --i binaries/__hosts_k.zip --o binaries/__hosts_k_zip.i
./binaries/bin2hex --i binaries/__hosts_o.zip --o binaries/__hosts_o_zip.i
