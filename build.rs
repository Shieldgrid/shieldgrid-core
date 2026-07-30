fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/velociraptor/api.proto");
    tonic_prost_build::compile_protos("proto/velociraptor/api.proto")?;
    Ok(())
}
