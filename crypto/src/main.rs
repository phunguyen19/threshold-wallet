use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name="shamir", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Say hello to someone
    Hello {
        #[arg(short, long)]
        name: String,
    },
    /// Say goodbye to someone
    Goodbye {
        #[arg(short, long)]
        name: String,
    },
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Hello { name } => println!("Hello, {}!", name),
        Commands::Goodbye { name } => println!("Goodbye, {}!", name),
    }
}
