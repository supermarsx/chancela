fn main() {
    // Generates the Tauri build-time glue (reads tauri.conf.json, embeds the
    // capability files, wires platform metadata). Standard Tauri v2 build hook.
    tauri_build::build();
}
