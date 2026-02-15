use std::path::Path;

#[test]
fn keeps_split_module_roots_for_models_zms_zts() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let legacy_roots = [
        "models.rs",
        "zms.rs",
        "zts.rs",
        "models/zms.rs",
        "models/zts.rs",
    ];

    let stale_files: Vec<&str> = legacy_roots
        .iter()
        .copied()
        .filter(|path| src.join(path).exists())
        .collect();

    assert!(
        stale_files.is_empty(),
        "legacy module roots found: {stale_files:?}; keep only mod.rs roots for models/zms/zts",
    );
}
