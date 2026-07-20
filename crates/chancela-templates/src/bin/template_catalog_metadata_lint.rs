use chancela_templates::catalog_metadata_lint::{
    catalog_metadata_report, validate_embedded_catalog_metadata,
};

fn main() {
    let issues = validate_embedded_catalog_metadata();
    if issues.is_empty() {
        return;
    }

    eprintln!("{}", catalog_metadata_report(&issues));
    std::process::exit(1);
}
