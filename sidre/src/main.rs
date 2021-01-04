use std::net::SocketAddr;

use sidre::{app, store};

const HELP: &str = "
sidre

USAGE:
    sidre [options]

FLAGS:
    -h, --help              Print this message

OPTIONS
    -p, --port             Port to run sidre on (default: 8080)
    -h, --host             Host to ruin sidre on (default: 0.0.0.0)
";

struct AppArgs {
    /// Port on which the app should run.
    port: i32,
    /// Host to run the app on.
    host: String,
}

// Determine whether or not we should use the persistent store.
//
// Currently this is just based on compile time features but I can imagine a
// world where we may want to compile both features and chose one or the other
// based on a command line flag or environment variable.
fn should_use_persistent_store() -> bool {
    !cfg!(feature = "data-in-memory")
}

fn parse_args() -> Result<AppArgs, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();
    if pargs.contains(["-h", "--help"]) {
        eprintln!("{}", HELP);
        std::process::exit(1);
    }

    let args = AppArgs {
        port: pargs.opt_value_from_str(["-p", "--port"])?.unwrap_or(8080),
        host: pargs
            .opt_value_from_str(["-h", "--host"])?
            .unwrap_or_else(|| "0.0.0.0".into()),
    };

    Ok(args)
}

#[tokio::main]
async fn main() {
    let args = parse_args().expect("Failed to parse args");

    let store = if should_use_persistent_store() {
        unimplemented!()
    } else {
        store::MemoryStore::new().expect("Failed to construct in-memory store")
    };

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .expect("Invalid address");

    // Run the app on 0.0.0.0 so that it works in a container.
    warp::serve(app(store).await).run(addr).await;
}
