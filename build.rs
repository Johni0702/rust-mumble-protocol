use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    // Prepare OUT_DIR/proto directory
    let out_dir = Path::new(&env::var("OUT_DIR").unwrap()).join("proto");
    fs::create_dir_all(&out_dir).expect("Failed to create $OUT_DIR/proto directory");

    protobuf_codegen_pure::Codegen::new()
        .out_dir(&out_dir)
        .inputs(&[if cfg!(feature = "webrtc-extensions") {
            "protos/MumbleWithWebRTC.proto"
        } else {
            "protos/Mumble.proto"
        }])
        .includes(&["protos"])
        .customize(protobuf_codegen_pure::Customize {
            generate_accessors: Some(true),
            ..Default::default()
        })
        .run()
        .expect("protoc");

    // Create mod.rs (see https://github.com/stepancheg/rust-protobuf/issues/324)
    let content = if cfg!(feature = "webrtc-extensions") {
        "mod MumbleWithWebRTC; pub use MumbleWithWebRTC::*;"
    } else {
        "mod Mumble; pub use Mumble::*;"
    };
    let mut file = fs::File::create(out_dir.join("mod.rs")).unwrap();
    file.write_all(content.as_bytes())
        .expect("Failed to write proto/mod.rs")
}
