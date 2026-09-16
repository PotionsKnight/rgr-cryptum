#!/usr/bin/env bash
set -euo pipefail

LIBRARY_DIRECTORY=/usr/local/lib/cryptum
EXECUTABLE_LINK=/usr/local/bin/cryptum
LIBRARIES=(libsubstitution.so libbeaufort.so libtrithemius.so)

if [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh: administrative rights are required" >&2
	exit 1
fi

if [ -L "$EXECUTABLE_LINK" ] && [ "$(readlink "$EXECUTABLE_LINK")" = "$LIBRARY_DIRECTORY/cryptum" ]; then
	rm -f "$EXECUTABLE_LINK"
fi

for file in cryptum "${LIBRARIES[@]}"; do
	rm -f "$LIBRARY_DIRECTORY/$file"
done
rmdir "$LIBRARY_DIRECTORY" 2>/dev/null || true

echo "cryptum removed"
