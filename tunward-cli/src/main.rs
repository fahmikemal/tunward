use clap::Parser;
use std::io;
use std::str::FromStr;
use tracing::warn;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::Directive;
use tunward::LocalProtocol;
use tunward::config::{ClientCreationRequest, ServerCreationRequest};
use tunward::executor::DefaultTokioExecutor;
use tunward::tunnel::ca_reloader::SystemCaReloader;
use tunward::{run_client, run_server};

#[cfg(feature = "jemalloc")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Use Websocket or HTTP2 protocol to tunnel {TCP,UDP} traffic
/// tunwardClient <---> tunwardServer <---> RemoteHost
#[derive(clap::Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment, long_about = None)]
pub struct Tunward {
    #[command(subcommand)]
    commands: Commands,

    /// Disable color output in logs
    #[arg(long, global = true, verbatim_doc_comment, env = "NO_COLOR")]
    no_color: bool,

    /// Control the number of threads that will be used.
    /// By default, it is equal the number of cpus
    #[arg(
        long,
        global = true,
        value_name = "INT",
        verbatim_doc_comment,
        env = "TOKIO_WORKER_THREADS",
        value_parser = clap::value_parser!(u32).range(1..=1024)
    )]
    nb_worker_threads: Option<u32>,

    /// Control the log verbosity. i.e: TRACE, DEBUG, INFO, WARN, ERROR, OFF
    /// for more details: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax
    #[arg(
        long,
        global = true,
        value_name = "LOG_LEVEL",
        verbatim_doc_comment,
        env = "RUST_LOG",
        default_value = "INFO"
    )]
    log_lvl: String,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    Client(Box<ClientCreationRequest>),
    Server(Box<ServerArgs>),
    /// Reload a running server through its private Unix control socket and wait for acknowledgment.
    Reload(ReloadArgs),
}

#[derive(clap::Args, Debug)]
pub struct ReloadArgs {
    #[arg(long, value_name = "PATH")]
    socket: std::path::PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct ServerArgs {
    /// Validate server arguments and referenced files, then exit without starting services.
    #[arg(short = 't', long)]
    test_config: bool,
    /// Reload policy and TLS files as one validated generation on SIGHUP (Unix).
    #[arg(long)]
    graceful_reload: bool,
    /// Private Unix control socket for acknowledged reload. Implies --graceful-reload.
    #[arg(long, value_name = "PATH")]
    reload_socket: Option<std::path::PathBuf>,
    #[command(flatten)]
    config: ServerCreationRequest,
}

fn main() -> anyhow::Result<()> {
    let args = Tunward::parse();
    if let Commands::Reload(reload) = &args.commands {
        #[cfg(unix)]
        {
            let status = tunward::reload_socket::request_reload(&reload.socket)?;
            println!(
                "tunward: configuration reload applied (generation {}, disconnected sessions {})",
                status.generation, status.disconnected_sessions
            );
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            let _ = reload;
            anyhow::bail!("The reload control socket is available on Unix servers only");
        }
    }
    if let Commands::Server(server) = &args.commands {
        #[cfg(not(unix))]
        if server.graceful_reload || server.reload_socket.is_some() {
            anyhow::bail!("CLI graceful reload is available on Unix servers; library users can use ServerReload");
        }
        #[cfg(unix)]
        if let Some(socket) = &server.reload_socket {
            tunward::reload_socket::validate_reload_socket_path(socket)?;
        }
    }
    if let Commands::Server(server) = &args.commands
        && server.test_config
    {
        EnvFilter::builder().parse(&args.log_lvl)?;
        tunward::check_server_config(&server.config)?;
        if server.config.allow_insecure_dev {
            eprintln!(
                "tunward: WARNING: --allow-insecure-dev is active. Cleartext/unauthenticated non-loopback connections are permitted. DO NOT USE IN PRODUCTION."
            );
        }
        eprintln!("tunward: configuration test is successful");
        return Ok(());
    }

    // Setup logging
    let mut env_filter = EnvFilter::builder().parse(&args.log_lvl).expect("Invalid log level");
    if !(args.log_lvl.contains("h2::") || args.log_lvl.contains("h2=")) {
        env_filter = env_filter.add_directive(Directive::from_str("h2::codec=off").expect("Invalid log directive"));
    }
    let logger = tracing_subscriber::fmt()
        .with_ansi(!args.no_color)
        .with_env_filter(env_filter);

    // stdio tunnel capture stdio, so need to log into stderr
    if let Commands::Client(args) = &args.commands {
        if args
            .local_to_remote
            .iter()
            .filter(|x| matches!(x.local_protocol, LocalProtocol::Stdio { .. }))
            .count()
            > 0
        {
            logger.with_writer(io::stderr).init();
        } else {
            logger.init()
        }
    } else {
        logger.init();
    };
    if let Err(err) = fdlimit::raise_fd_limit() {
        warn!("Failed to set soft file limit to hard file limit: {}", err)
    }

    // Build the Tokio runtime
    let mut builder = match args.nb_worker_threads {
        Some(1) => tokio::runtime::Builder::new_current_thread(),
        Some(n) => {
            let mut b = tokio::runtime::Builder::new_multi_thread();
            b.worker_threads(n as usize);
            b
        }
        None => tokio::runtime::Builder::new_multi_thread(),
    };
    let rt = builder.enable_all().build()?;

    rt.block_on(async move {
        // Start system CA reloader
        SystemCaReloader::start(None);

        match args.commands {
            Commands::Client(args) => run_client(*args, DefaultTokioExecutor::default()).await?,
            Commands::Server(args) => {
                if args.graceful_reload || args.reload_socket.is_some() {
                    let reload = tunward::reload::ServerReload::default();
                    #[cfg(unix)]
                    {
                        if let Some(path) = &args.reload_socket {
                            let socket = tunward::reload_socket::ReloadSocket::bind(path)?;
                            tokio::spawn(socket.serve(reload.clone()));
                        }
                        let mut signals = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
                        let control = reload.clone();
                        tokio::spawn(async move {
                            while signals.recv().await.is_some() {
                                if let Err(error) = control.reload().await {
                                    tracing::warn!("SIGHUP reload failed: {error:#}");
                                }
                            }
                        });
                    }
                    tunward::run_server_with_reload(args.config, DefaultTokioExecutor::default(), reload).await?;
                } else {
                    run_server(args.config, DefaultTokioExecutor::default()).await?;
                }
            }
            Commands::Reload(_) => unreachable!("reload handled before runtime startup"),
        }

        Ok(())
    })
}
