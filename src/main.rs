/*
    shellcode-myner
    A tool used to extract shellcode from an object/binary file.

    Copyright (C) 2022  winterrdog

    This file is part of shellcode-myner.

    shellcode-myner is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    shellcode-myner is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>

    CONTACT:
        - Email: winterrdog@protonmail.ch
        - Telegram: https://t.me/winterrdog
*/
extern crate lazy_static;
extern crate regex;
extern crate textwrap;

use lazy_static::lazy_static; // for statically compiling regexes
use regex::Regex; // For regular expressions
use std::process::{Command, Output};
use std::{env, str}; // to run objdump
use textwrap::wrap;

fn validate_line(line: &str) -> bool {
    // ref: https://docs.rs/regex/latest/regex/#example-avoid-compiling-the-same-regex-in-a-loop
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^[0-9a-f]+:.*$").unwrap();
    }

    RE.is_match(line)
}

fn extract_opcodes(opcode_text: &str) -> regex::Matches<'_, '_> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"[0-9a-f][0-9a-f]").unwrap();
    }

    RE.find_iter(opcode_text)
}

fn main() {
    // Run objdump to obtain the text segment's opcodes
    let objdp_out: Output = Command::new("objdump")
        .args([
            "-d",
            env::args()
                .nth(1)
                .unwrap_or_else(|| "".to_string())
                .as_str(),
        ])
        .output()
        .expect("[-] objdump failed to execute!");

    let str_output: &str = str::from_utf8(&objdp_out.stdout).unwrap_or("");

    // Only process if there's output from objdump
    if !str_output.is_empty() {
        let lines = str_output
            .split('\n')
            .map(|x| x.trim())
            .collect::<Vec<&str>>();

        let mut sh_code: String = String::new();
        let mut sh_code_len: usize = 0;

        // Get disassembly from objdump output
        for each_single_line in &lines {
            // If there's sth to process
            if !each_single_line.trim().is_empty() && validate_line(each_single_line) {
                let asm_and_opcodes: &str = each_single_line
                    .split(':')
                    .map(|x| x.trim())
                    .collect::<Vec<&str>>()[1];

                // Extracting shellcode from objdump output
                let opcodes: &str = asm_and_opcodes.split('\t').collect::<Vec<&str>>()[0];
                for each_opcode in extract_opcodes(opcodes) {
                    sh_code.push_str("\\x");
                    sh_code.push_str(each_opcode.as_str());
                    sh_code_len += 1;
                }
            }
        }

        // Display extracted shellcode
        println!("\n\t\t⭐ shellcode-myner by winterrdog ⭐\n\t\t🥂 Github: https://github.com/winterrdog \n\t\t🔊 Email: winterrdog@protonmail.ch");
        println!("\nShellcode length: {} bytes.", sh_code_len);

        // Printing shellcode
        println!("Shellcode:");
        let wrapped_lines: Vec<std::borrow::Cow<str>> = wrap(sh_code.as_str(), 56);
        for each_wrp_ln in &wrapped_lines {
            println!("{}", each_wrp_ln);
        }
    } else {
        eprintln!(
            "From winterrdog,\n[-] shellcode-myner is either: 
            [1] NOT provided a binary( at the cmdline ) to extract from shellcode.
                Usage:  cargo run <binary_to_scan>
                                    OR
                        target/debug/shellcode-myner <binary_to_inspect>

            [2] NOT installed
                Please use your package manager to install 'binutils' or download and install
                them from the Internet e.g. for UNIX systems, check for installation procedures at
                https://command-not-found.com/objdump."
        );
    }
}
