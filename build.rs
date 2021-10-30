
fn main() {
    println!("cargo:rerun-if-changed=src/dbgeng/*.cpp");
    let mut build = cc::Build::new();
    build.file("src/dbgeng/dbgeng.cpp").compile("dbgeng");
}