fn main() -> anyhow::Result<()> {
    let _ = tuta_bridge::adapters::cli::parse_from(std::env::args_os())?;
    Ok(())
}
