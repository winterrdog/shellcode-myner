#!/usr/bin/env bash

cargo build --release
mv -u ./target/release/shellcode-myner .

printf "\e[1;96m \n[+] Now, you can run shellcode-myner like this:\n \e[0m"
printf "\e[1;93m \t./shellcode-myner <binary_to_inspect> \e[0m"
