use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use clap::Parser;

#[derive(Parser)]
#[command(name = "argon2-cli")]
#[command(author = "Your Name <your.email@example.com>")]
#[command(version = "1.0")]
#[command(about = "Generate Argon2 password hashes", long_about = None)]
struct Cli {
    /// The password to hash
    #[arg(short, long)]
    password: String,

    /// Optional salt (will be generated if not provided)
    #[arg(short, long)]
    salt: Option<String>,

    /// Use consistent test parameters (less secure, but faster and consistent)
    #[arg(short, long)]
    test_params: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Use either provided salt or generate a new one
    let salt = match cli.salt {
        Some(s) => SaltString::from_b64(&s).expect("Salt Error"),
        None => SaltString::generate(&mut OsRng),
    };

    // Configure Argon2 parameters
    let argon2 = if cli.test_params {
        // Test parameters - faster but less secure
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(19456, 2, 1, None).expect("Argon init error"),
        )
    } else {
        // Production parameters - more secure but slower
        Argon2::default()
    };

    // Generate the hash
    let password_hash = argon2
        .hash_password(cli.password.as_bytes(), &salt).expect("Password Hash Error")
        .to_string();

    // Print the results
    println!("Password: {}", cli.password);
    println!("Salt (b64): {}", salt);
    println!("Hash: {}", password_hash);

    Ok(())
}
