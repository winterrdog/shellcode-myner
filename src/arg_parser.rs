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
use clap::{self, arg, Arg};

#[must_use]
pub fn parse_cmd_args<'a>() -> clap::Command<'a> {
    clap::Command::new("shellcode-myner")
        .version("1.0.1")
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
            Arg::new("output")
                .short('o')
                .takes_value(true)
                .help("Specify the file or file path where the shellcode will be saved to."),
        ])
}
