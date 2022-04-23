#!/usr/bin/env bash

cargo build --release
mv -u ./target/release/shellcode-myner .

printf "\e[1;96m \n[+] Removing artifacts...\n \e[0m"
cargo clean

printf "\e[1;96m \n[+] Now, you can run shellcode-myner like this to find out about its usage:\n \e[0m"
printf "\e[1;93m \t./shellcode-myner -h \e[0m"
