use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use scp2p_core::{Node, NodeConfig, NodeId, ShareId};

#[derive(Parser)]
#[command(name = "scp2p")]
#[command(about = "SCP2P reference CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenIdentity,
    PrintIds,
    Start,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenIdentity => {
            let mut rng = OsRng;
            let key = SigningKey::generate(&mut rng);
            println!("private_key: {}", hex::encode(key.to_bytes()));
            println!(
                "public_key: {}",
                hex::encode(key.verifying_key().to_bytes())
            );
        }
        Command::PrintIds => {
            let mut rng = OsRng;
            let key = SigningKey::generate(&mut rng);
            let pubkey = key.verifying_key();
            let node_id = NodeId::from_pubkey(&pubkey);
            let share_id = ShareId::from_pubkey(&pubkey);
            println!("node_id: {}", hex::encode(node_id.0));
            println!("share_id: {}", hex::encode(share_id.0));
        }
        Command::Start => {
            let _node = Node::start(NodeConfig::default()).await?;
            println!("node started (v0.1 skeleton)");
        }
    }

    Ok(())
}
