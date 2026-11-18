//! Rewrites the conformance archives in `tests/fixtures`.
//!
//! `cargo run --example write_fixtures`. Rewriting (a) is a format change, so it is done only
//! when the writer's bytes are meant to change.

#[path = "../tests/support/fixtures.rs"]
mod fixtures;

fn main() -> std::io::Result<()> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir)?;
    fixtures::write_all(&dir)?;
    println!("wrote the fixtures to {}", dir.display());
    Ok(())
}
