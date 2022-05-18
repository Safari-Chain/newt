use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// arguement for multiscript
    args: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // if let Some(args) = cli.args.as_deref() {
    //     println!("Arguement passed: {}", args);
    // }

    // let multiscript = String::from("multiscript");
    match cli.args {
        Some(command) => {
            if command == "multiscript" {
                println!("Your command is: {:?}", command);
            } 
            println!("No matching commands")
        },
        None => println!("No matching commands")
    }
    println!("hello cli");
}

/*
accept comands from the user in the terminal
print the result to the console
commands to accept include:
1. command for each heuristic e.g. cargo run --multiscript
(a) multiscript
    cargo run --multiscript transaction-hex
(b) address-reuse
    cargo run --addressreuse transaction-hex
(c) round-number
    cargo run --roundnumber transaction-hex
(d) equal-output coinjoin
    cargo run --coinjoin transaction-hex
(e) unnecessary inputs
    cargo run --unnecessaryinputs transaction-hex
(f) common input ownership
    cargo run --commonownership transaction-hex
2. command for all heuristics (transaction analysis)
3. command for generating transaction template
*/
