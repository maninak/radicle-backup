//! `rad-backup`, which `rad` runs from `PATH` as `rad backup`.

fn main() -> std::process::ExitCode {
    radicle_backup::main()
}
