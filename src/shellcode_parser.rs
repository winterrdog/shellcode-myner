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

use crate::{arg_parser::parse_cmd_args, myner_regex};
use clap::ArgMatches;
use std::{fs::File, io::Write, process::Command, str};
use textwrap::wrap; // to run objdump // for cmd-line args parsing

#[derive(Debug, Default)]
pub struct ShellcodeMyner<'a> {
    sh_code: String,
    sh_code_len: usize,
    objdmp_out: String,
    objdmp_lines: Vec<&'a str>,
}

impl<'a> ShellcodeMyner<'a> {
    /*
        Extracts shellcode from the passed in raw objdump output and prints it to screen
    */

    fn save_shellcode(&self, arg_handle: &ArgMatches) {
        let fname = "extracted_shellcode.c";
        let file_path = std::path::Path::new(fname);
        if file_path.exists() {
            println!("File, {:?}, already exists!", fname);
            return;
        }

        let mut fh = File::create(fname).expect("Failed to create file");
        let content = if arg_handle.is_present("array") {
            format!(
                "#include <stdio.h>\n#include <stdlib.h>\n\nstatic unsigned char shellcode[] =\n{{ {} }};\n",
                self.sh_code
            )
        } else {
            format!(
                "#include <stdio.h>\n#include <stdlib.h>\n\nstatic const char *const shellcode =\n\"{}\n",
                self.sh_code
            )
        };

        let res_write = fh.write_all(content.as_bytes());
        std::mem::drop(res_write);

        println!(
            "\n[+] Shellcode saved to: {:?}.",
            file_path.canonicalize().unwrap().as_os_str()
        );
    }

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

    pub fn run(&'a mut self) {
        let mut arg_vec_handle = parse_cmd_args();
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
            self.sh_code_arr_fmt(&arg_vec);
        } else if arg_vec.is_present("string") {
            self.sh_code_str_fmt(&arg_vec);
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

    fn sh_code_arr_fmt(&'a mut self, arg_handle: &ArgMatches) {
        self.objdmp_lines = self.objdmp_out.split('\n').map(str::trim).collect();

        for each_single_line in &self.objdmp_lines {
            if myner_regex::validate_line(each_single_line) && !each_single_line.trim().is_empty() {
                let asm_and_opcodes: &str = each_single_line
                    .split(':')
                    .map(str::trim)
                    .collect::<Vec<&str>>()[1];

                // Extracting shellcode from objdump output
                let opcodes: &str = asm_and_opcodes.split('\t').collect::<Vec<&str>>()[0];
                for each_opcode in myner_regex::extract_opcodes(opcodes) {
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
            if myner_regex::validate_line(each_single_line) && !each_single_line.trim().is_empty() {
                let asm_and_opcodes: &str = each_single_line
                    .split(':')
                    .map(str::trim)
                    .collect::<Vec<&str>>()[1];

                // Extracting shellcode from objdump output
                let opcodes: &str = asm_and_opcodes.split('\t').collect::<Vec<&str>>()[0];
                for each_opcode in myner_regex::extract_opcodes(opcodes) {
                    self.sh_code.push_str(r#"\x"#);
                    self.sh_code.push_str(each_opcode.as_str());
                    self.sh_code_len += 1;
                }
            }
        }

        self.sh_code.push_str(r#"";"#);

        self.display_intro();
        print!(r#"""#);
        self.display_wrapped_output(false);

        self.save_shellcode(arg_handle);
    }

    // fn usage_error_msg() {
    //     eprintln!(
    //         "From winterrdog,\n[-] shellcode-myner is either:
    //     [1] NOT provided a binary( at the cmdline ) to extract from shellcode.
    //         Usage:  cargo run <binary_to_scan>
    //                             OR
    //                 ./shellcode-myner <binary_to_inspect>

    //     [2] 'binutils' NOT installed
    //         Please use your package manager to install 'binutils' or download and install
    //         them from the Internet e.g. for UNIX systems, check for installation procedures at
    //         https://command-not-found.com/objdump."
    //     );
    // }
}
