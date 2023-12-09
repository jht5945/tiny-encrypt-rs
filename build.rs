#[cfg(feature = "secure-enclave")]
use swift_rs::SwiftLinker;

fn main() {
    // Ensure this matches the versions set in your `Package.swift` file.
    #[cfg(feature = "secure-enclave")]
    SwiftLinker::new("11")
        .with_ios("11")
        .with_package("swift-lib", "./swift-lib/")
        .link();
}