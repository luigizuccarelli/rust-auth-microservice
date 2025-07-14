// module schema
use clap::Parser;

/// cli struct
#[derive(Parser, Debug)]
#[command(name = "rust-auth-microservice")]
#[command(author = "Luigi Mario Zuccarelli <luigizuccarelli@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "Auth JWT token generate and verify", long_about = None)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// config file to use
    #[arg(short, long, value_name = "config")]
    pub config: String,
}
