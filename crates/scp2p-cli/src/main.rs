// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod shell;

use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

/// SCP2P interactive command-line interface.
///
/// No subcommands - the shell guides you through all operations
/// interactively. Use arrow keys to navigate menus and Escape to go back.
#[derive(Parser)]
#[command(name = "scp2p", version)]
struct Args {
    /// Path to the SQLite state database.
    #[arg(long, default_value = "scp2p.db", env = "SCP2P_DB")]
    db: String,

    /// Bootstrap peer addresses (IP:PORT) - comma-separated or repeated.
    #[arg(
        long = "bootstrap",
        value_name = "IP:PORT",
        env = "SCP2P_BOOTSTRAP",
        value_delimiter = ',',
        num_args = 0..
    )]
    bootstrap: Vec<String>,

    /// TCP port this node listens on for incoming peer connections.
    #[arg(long, default_value_t = 7001, env = "SCP2P_PORT")]
    port: u16,

    /// Log level: error, warn, info, debug, trace.
    /// Can also be set via RUST_LOG (e.g. RUST_LOG=scp2p_core=debug).
    #[arg(long, default_value = "warn", env = "SCP2P_LOG")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialise tracing. RUST_LOG overrides --log-level when set.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));
    fmt().with_env_filter(filter).with_target(false).init();

    shell::run(args.db, args.bootstrap, args.port).await
}
