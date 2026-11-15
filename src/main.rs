fn main() -> anyhow::Result<()> {
    match tuta_bridge::adapters::cli::parse_from(std::env::args_os()) {
        Ok(_) => Ok(()),
        Err(e) => e.exit(),
    }
}
