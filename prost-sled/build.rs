use prost_build::compile_protos;

fn main() {
    compile_protos(&["src/messages.proto"], &["src".into()])
        .expect("failed to build protos");
}
