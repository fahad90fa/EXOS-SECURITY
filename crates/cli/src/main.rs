use clap::{Parser, Subcommand};
use nexus_cli::commands;

#[derive(Parser)]
#[command(name = "nexus")]
#[command(about = "Nexus Sentinel - Advanced Web Application Security Scanner")]
#[command(version, author)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy server
    Proxy {
        /// Listen address (default: 127.0.0.1:8080)
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        listen: String,

        /// Upstream proxy (optional)
        #[arg(long)]
        upstream: Option<String>,

        /// Enable intercept mode
        #[arg(long)]
        intercept: bool,
    },

    /// Crawl a website for URLs and forms
    Crawl {
        /// Target URL
        url: String,

        /// Maximum crawl depth
        #[arg(short, long, default_value = "5")]
        depth: u32,

        /// Maximum URLs to crawl
        #[arg(short, long, default_value = "1000")]
        max_urls: usize,

        /// Concurrency level
        #[arg(short, long, default_value = "10")]
        concurrency: usize,

        /// Output format (json, table)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Run a security scan
    Scan {
        /// Target URL
        url: String,

        /// Scan type (full, active, passive, crawl, api)
        #[arg(short, long, default_value = "full")]
        scan_type: String,

        /// Output format (json, table, pretty)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Save results to file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Start the API server
    Api {
        /// Listen address (default: 127.0.0.1:3000)
        #[arg(short, long, default_value = "127.0.0.1:3000")]
        listen: String,
    },

    /// Fuzz a parameter
    Fuzz {
        /// Target URL
        url: String,

        /// Parameter to fuzz
        #[arg(short, long)]
        param: String,

        /// Wordlist file
        #[arg(short, long)]
        wordlist: Option<String>,

        /// Number of threads
        #[arg(short, long, default_value = "10")]
        threads: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Proxy { listen, upstream, intercept } => {
            commands::proxy::run(listen, upstream, intercept).await?;
        }
        Commands::Crawl { url, depth, max_urls, concurrency, format } => {
            commands::crawl::run(url, depth, max_urls, concurrency, format).await?;
        }
        Commands::Scan { url, scan_type, format, output } => {
            commands::scan::run(url, scan_type, format, output).await?;
        }
        Commands::Api { listen } => {
            commands::api::run(listen).await?;
        }
        Commands::Fuzz { url, param, wordlist, threads } => {
            commands::fuzz::run(url, param, wordlist, threads).await?;
        }
    }

    Ok(())
}
