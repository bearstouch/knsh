fn main() {
    // TODO: parse arguments
    let value = std::env::args().nth(1).unwrap();
    println!("{value}");
}
