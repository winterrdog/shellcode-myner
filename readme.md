# 🔍 INTRODUCTION WITH SOME HISTORY
`shellcode-myner` is a small hobby project I created to make the process of extracting shellcode from binaries less painful because initially I always had to use `readelf` to get section information ,`dd` to extract the opcodes and `xxd` to reformat `dd`'s output to better fit the style of shellcode output I wanted but with `shellcode-myner` all I needed was a binary file😊. 

I hope it will speedup your exploitation workflow.
# 📚 PREREQUISITES
* Target operating system: A Unix-like OS e.g. MacOS, GNU/Linux, FreeBSD, OpenBSD, GhostBSD.
* **objdump** should be installed. _In case objdump is not installed on your system, follow these [instructions](https://command-not-found.com/objdump) on how to do that._
* **Rust** and **Cargo** should be installed. _In case they're not installed on your system, you can follow these [instructions](https://www.rust-lang.org/tools/install) on how to do that._
* Some commandline-Fu.

# ⚙👷 HOW IT WORKS
* `shellcode-myner` is given a binary file to inspect and parse at the command line.
* It executes objdump to disassemble the binary's text section and the output of the operation is fed into the analyzer.
* The analyzer parses each line of output for the shellcode using regex.
* The output of the analysis is printed on screen as a string of shellcode, in a format like this `\x32\xa4\xc2...`.

# 🔧🔨 USAGE 
1. Clone this repository( You can also just download it. )

    ```sh
    git clone https://github.com/winterrdog/shellcode-myner.git
    ```

2. You can run this program in 2 ways:

    * Using Cargo for both compilation and execution of the program

        ```sh
        cargo run <binary_to_inspect>
        ```

    * Using Cargo for compilation only and then manually run it at the command-line( Condition: You must be in the `shellcode-myner` main directory ):
            
        ```sh
        cargo build
        target/debug/shellcode-myner <binary_to_inspect>
        ```
    ## OPTIONAL:
    * You can choose to make a symbolic link for the `shellcode-myner` executable like so:
    ```sh
    sudo ln -fs <absolute_path_shellcode_myner> /usr/bin/shellcode-myner
    ```
    #### OR
    * Add it to your `PATH` environment variable.

# 📝 NOTES
* `shellcode-myner` is GPLv3 licensed, feel free to contribute something to the project even if it's a typo 😊, or take it a step further by forking and extending it.