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
#![warn(clippy::pedantic, clippy::all)]

extern crate clap;
extern crate lazy_static;
extern crate regex;
extern crate textwrap;

use clap::{arg, Arg};
use lazy_static::lazy_static; // for statically compiling regexes
use regex::Regex; // For regular expressions
use std::{process::Command, str};
use textwrap::wrap; // to run objdump // for cmd-line args parsing

#[derive(Debug, Default)]
pub struct ShellcodeMyner<'a> {
    sh_code: String,
    sh_code_len: usize,
    objdmp_out: String,
    objdmp_lines: Vec<&'a str>,
}

#[allow(dead_code)]
impl<'a> ShellcodeMyner<'a> {
    /*
        Extracts shellcode from the passed in raw objdump output and prints it to screen
    */

    fn display_intro(&self) {
        // Display extracted shellcode
        println!("\n\t\t⭐ shellcode-myner by winterrdog ⭐\n\t\t🥂 Github: https://github.com/winterrdog \n\t\t🔊 Email: winterrdog@protonmail.ch");
        println!("\nShellcode length: {} bytes.", self.sh_code_len);

        // Printing shellcode
        println!("shellcode[] =");
    }

    fn display_wrapped_output(&self, indent: bool) {
        let wrapped_lines: Vec<std::borrow::Cow<str>> = wrap(self.sh_code.as_str(), 56);

        if indent {
            for each_wrp_ln in &wrapped_lines {
                println!("  {}", each_wrp_ln);
            }
        } else {
            for each_wrp_ln in &wrapped_lines {
                println!("{}", each_wrp_ln);
            }
        }
    }

    fn extract_opcodes(opcode_text: &str) -> regex::Matches<'_, '_> {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"[0-9a-f][0-9a-f]").unwrap();
        }

        RE.find_iter(opcode_text)
    }

    fn parse_cmd_args() -> clap::Command<'a> {
        clap::Command::new("shellcode-myner")
            .version("1.0.0")
            .author("winterrdog <winterrdog@protonmail.ch>")
            .about(r#"A tool used to "painlessly" extract shellcode from an object/binary file."#)
            .args(&[
                arg!(<BINARY> "Binary/Object file to extract from shellcode."),
                Arg::new("array")
                    .short('a')
                    .takes_value(false)
                    .required_unless_present("string")
                    .conflicts_with("string")
                    .help("Outputs the shellcode in form of C-style array."),
                Arg::new("string")
                    .short('s')
                    .takes_value(false)
                    .conflicts_with("array")
                    .help("Outputs the shellcode in form of C-style character string format"),
            ])
    }

    pub fn run(&'a mut self) {
        let mut arg_vec_handle = ShellcodeMyner::parse_cmd_args();
        let arg_vec = arg_vec_handle.get_matches_mut();
        let tgt_bin = if let Some(name) = arg_vec.value_of("BINARY") {
            name
        } else {
            ""
        };

        self.run_child_proc("objdump", tgt_bin);

        if self.objdmp_out.is_empty() {
            let _m = arg_vec_handle.print_long_help();
        } else if arg_vec.is_present("array") {
            self.sh_code_arr_fmt();
        } else if arg_vec.is_present("string") {
            self.sh_code_str_fmt();
        } else {
            println!(r#"[-] You have to pass at most one of these 2 options: "-a" or "-s"."#,);
            let _n = arg_vec_handle.print_long_help();
        }
    }

    fn run_child_proc(&mut self, child_prog: &str, prog_name: &str) {
        if !prog_name.is_empty() {
            let program_out = Command::new(child_prog)
                .args(["-d", prog_name])
                .output()
                .expect("[-] objdump failed to execute!");

            self.objdmp_out = String::from_utf8(program_out.stdout).unwrap_or_default();
        }
    }

    fn sh_code_arr_fmt(&'a mut self) {
        self.objdmp_lines = self.objdmp_out.split('\n').map(str::trim).collect();

        for each_single_line in &self.objdmp_lines {
            if ShellcodeMyner::validate_line(each_single_line)
                && !each_single_line.trim().is_empty()
            {
                let asm_and_opcodes: &str = each_single_line
                    .split(':')
                    .map(str::trim)
                    .collect::<Vec<&str>>()[1];

                // Extracting shellcode from objdump output
                let opcodes: &str = asm_and_opcodes.split('\t').collect::<Vec<&str>>()[0];
                for each_opcode in ShellcodeMyner::extract_opcodes(opcodes) {
                    self.sh_code.push_str("0x");
                    self.sh_code.push_str(each_opcode.as_str());
                    self.sh_code.push_str(", ");
                    self.sh_code_len += 1;
                }
            }
        }

        self.display_intro();

        for _ in 0..2 {
            self.sh_code.pop();
        }

        println!("{{");
        self.display_wrapped_output(true);
        println!("}};");
    }

    fn sh_code_str_fmt(&'a mut self) {
        self.objdmp_lines = self.objdmp_out.split('\n').map(str::trim).collect();

        for each_single_line in &self.objdmp_lines {
            if ShellcodeMyner::validate_line(each_single_line)
                && !each_single_line.trim().is_empty()
            {
                let asm_and_opcodes: &str = each_single_line
                    .split(':')
                    .map(str::trim)
                    .collect::<Vec<&str>>()[1];

                // Extracting shellcode from objdump output
                let opcodes: &str = asm_and_opcodes.split('\t').collect::<Vec<&str>>()[0];
                for each_opcode in ShellcodeMyner::extract_opcodes(opcodes) {
                    self.sh_code.push_str("\\x");
                    self.sh_code.push_str(each_opcode.as_str());
                    self.sh_code_len += 1;
                }
            }
        }

        self.sh_code.push_str("\";");

        self.display_intro();
        print!("\"");
        self.display_wrapped_output(false);
    }

    fn usage_error_msg() {
        eprintln!(
            "From winterrdog,\n[-] shellcode-myner is either: 
        [1] NOT provided a binary( at the cmdline ) to extract from shellcode.
            Usage:  cargo run <binary_to_scan>
                                OR
                    ./shellcode-myner <binary_to_inspect>

        [2] 'binutils' NOT installed
            Please use your package manager to install 'binutils' or download and install
            them from the Internet e.g. for UNIX systems, check for installation procedures at
            https://command-not-found.com/objdump."
        );
    }

    fn validate_line(line: &str) -> bool {
        // ref: https://docs.rs/regex/latest/regex/#example-avoid-compiling-the-same-regex-in-a-loop
        lazy_static! {
            static ref RE: Regex = Regex::new(r"^[0-9a-f]+:.*$").unwrap();
        }

        RE.is_match(line)
    }
}
