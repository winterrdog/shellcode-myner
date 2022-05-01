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

use lazy_static::lazy_static; // for statically compiling regexes
use regex::Regex; // For regular expressions

pub fn extract_opcodes(opcode_text: &str) -> regex::Matches<'_, '_> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"[0-9a-f][0-9a-f]").unwrap();
    }

    RE.find_iter(opcode_text)
}

pub fn validate_line(line: &str) -> bool {
    // ref: https://docs.rs/regex/latest/regex/#example-avoid-compiling-the-same-regex-in-a-loop
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^[0-9a-f]+:.*$").unwrap();
    }

    RE.is_match(line)
}
