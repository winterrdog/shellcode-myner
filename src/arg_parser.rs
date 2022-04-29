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
        ])
}
