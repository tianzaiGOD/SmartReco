mod evm;
mod replay;
// mod r#move;

use clap::Parser;
use crate::evm::{evm_main, EvmArgs};
use crate::replay::{replay_main, ReplayEvmArgs};

use clap::Subcommand;


#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    EVM(EvmArgs),
    REPLAY(ReplayEvmArgs)
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::EVM(args) => {
            evm_main(args);
        },
        Commands::REPLAY(args) => {
            replay_main(args)
        }
    }

}
