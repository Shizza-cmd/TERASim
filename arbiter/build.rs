fn main() {
    println!("cargo:rerun-if-changed=../crypto/src/tera_crypt.c");
    println!("cargo:rerun-if-changed=../crypto/include/tera_crypt.h");
    cc::Build::new()
        .file("../crypto/src/tera_crypt.c")
        .include("../crypto/include")
        .compile("tera_crypt");
}
