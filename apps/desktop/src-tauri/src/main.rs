// Prevents an extra console window from opening on Windows in release builds.
// Keep this attribute — removing it makes the packaged app spawn a console.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // All app logic lives in the library crate so the same entry point can be
    // reused by the mobile targets (iOS/Android) Tauri v2 supports (ARC-04).
    chancela_desktop_lib::run();
}
