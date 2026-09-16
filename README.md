# cryptum

Command-line tool that encrypts and decrypts arbitrary data with a chosen algorithm.
Each cipher lives in its own dynamically loaded library.

Build with `cmake -S . -B build && cmake --build build`, then run `./build/bin/cryptum --help`.
Install with `sudo scripts/install.sh`. The full documentation is in `docs/documentation.txt`.
