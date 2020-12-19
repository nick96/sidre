use glob::glob;
use prost_build::compile_protos;

fn main() {
    let protos: Vec<String> = glob("protos/*.proto")
        .expect("failed to glob protos")
        // Ignore un-readable paths
        .filter_map(|path| path.ok().map(|p| p.to_string_lossy().to_string()))
        .collect();
    // We want to rerun the build script if any of the proto files are changed.
    // specifying the dir doesnn't necessarily mean this will happen and the rerun
    // directive doesn't support globs, so this is the easiest way to do it.
    for proto_file in &protos {
        println!("cargo:rerun-if-changed={}", proto_file);
    }

    compile_protos(&protos, &["protos".into()])
        .expect("failed to build protos");
}
