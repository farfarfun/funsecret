fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(funsecret::run(std::env::args_os()) as u8)
}
