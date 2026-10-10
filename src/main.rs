use rustscan_automator::cli;

fn main() {
    rustscan_automator::logging::init();

    if let Err(error) = cli::run() {
        eprintln!("error: {error}");
        std::process::exit(error.exit_code());
    }
}
