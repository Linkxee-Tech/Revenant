use std::env;

/// Real fix for the hardcoded `/home/claude/revenant-core/fixtures` paths
/// that appeared throughout the codebase — computed from the environment,
/// not baked into the binary.
///
/// HONEST SCOPE: only the Linux/macOS-shaped path (`$HOME/.local/share/...`)
/// is actually tested here, because this sandbox is Linux and there is no
/// way to verify Windows (`%LOCALAPPDATA%`) or a real macOS
/// (`~/Library/Application Support`) behavior without those platforms
/// present. The `cfg!` branches below encode the intended per-platform
/// paths so the logic is complete and correct-by-inspection, but only the
/// Linux branch has actually been exercised.
///
/// Resolution order:
/// 1. `REVENANT_DATA_DIR` env var — explicit override, checked first so a
///    user or test harness can always redirect this without touching code.
/// 2. Platform default under the real home directory.
/// 3. `./revenant-data` — last-resort relative fallback if no home
///    directory is discoverable at all (e.g. a stripped-down container).
pub fn data_dir() -> String {
    if let Ok(dir) = env::var("REVENANT_DATA_DIR") {
        return dir;
    }

    if cfg!(target_os = "windows") {
        if let Ok(local_appdata) = env::var("LOCALAPPDATA") {
            return format!("{local_appdata}\\Revenant");
        }
    } else if cfg!(target_os = "macos") {
        if let Ok(home) = env::var("HOME") {
            return format!("{home}/Library/Application Support/Revenant");
        }
    } else if let Ok(home) = env::var("HOME") {
        // Linux — the only branch actually verified in this environment.
        return format!("{home}/.local/share/revenant");
    }

    "./revenant-data".to_string()
}
