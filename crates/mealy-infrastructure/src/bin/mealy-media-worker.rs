//! Test/release-gate entry point for the fixed isolated media worker.

fn main() -> std::process::ExitCode {
    mealy_infrastructure::media_worker_main()
}
