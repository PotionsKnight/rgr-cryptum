#!/usr/bin/env bash
set -euo pipefail

LIBRARY_DIRECTORY=/usr/local/lib/cryptum
EXECUTABLE_LINK=/usr/local/bin/cryptum
LIBRARIES=(libsubstitution.so libbeaufort.so libtrithemius.so)

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_directory=${1:-$script_directory/../build/bin}

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: administrative rights are required" >&2
	exit 1
fi

for file in cryptum "${LIBRARIES[@]}"; do
	if [ ! -f "$source_directory/$file" ]; then
		echo "install.sh: '$source_directory/$file' not found, build the project first" >&2
		exit 1
	fi
done

install -d -m 0755 "$LIBRARY_DIRECTORY"
install -m 0755 "$source_directory/cryptum" "$LIBRARY_DIRECTORY/cryptum"
for file in "${LIBRARIES[@]}"; do
	install -m 0644 "$source_directory/$file" "$LIBRARY_DIRECTORY/$file"
done
ln -sfn "$LIBRARY_DIRECTORY/cryptum" "$EXECUTABLE_LINK"

echo "cryptum installed in $LIBRARY_DIRECTORY and linked as $EXECUTABLE_LINK"
