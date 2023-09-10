use clap::{Args, Parser, Subcommand};

#[allow(unused_imports)]
#[derive(Parser)]
#[clap(
    name = "pass",
    version = "0.1.0",
    author = "Ishan",
    about = "A easy-to-use CLI password manager and generator"
)]
struct Cli {
    /// Subcommand to do some operation like add, remove, etc.
    #[command(subcommand)]
    commands: Option<Commands>,
    //
    // /// Username of the account
    // #[clap(short = 'n', long = "name")]
    // username: String,
    //
    // /// Password of the account
    // #[clap(short = 'p', long = "password")]
    // password: String,
    //
    // /// URL of the site for which the password is
    // #[clap(short = 'u', long = "url")]
    // url: String,
    //
    // /// Notes for the account
    // #[clap(short = 'm', long = "msg", default_value = "", required = false)]
    // notes: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Make a new password
    Add(AddArgs),

    /// Remove a password
    Remove(RemoveArgs),

    /// Update a password
    Update(UpdateArgs),

    /// List all made password
    List(ListArgs),

    /// Get a password
    Get(GetArgs),

    /// Login to the pass
    Login(LoginArgs),

    /// Logout from the pass
    Logout(LogoutArgs),

    /// Create a new user
    CreateUser(CreateUserArgs),

    /// Remove a existing user
    RemoveUser(RemoveUserArgs),
}

#[derive(Args)]
struct AddArgs {}

#[derive(Args)]
struct RemoveArgs {}

#[derive(Args)]
struct UpdateArgs {}

#[derive(Args)]
struct ListArgs {}

#[derive(Args)]
struct GetArgs {}

#[derive(Args)]
struct LoginArgs {}

#[derive(Args)]
struct LogoutArgs {}

#[derive(Args)]
struct CreateUserArgs {}

#[derive(Args)]
struct RemoveUserArgs {}

fn main() {
    // Making a safe & secure, easy to use password manager and generator using clap and bcrypt

    println!("Welcome to the pass!");

    let args = Cli::parse();
    // println!("Username: {}", args.username);
    // println!("Password: {}", args.password);
    // println!("URL: {}", args.url);
    // println!("Notes: {}", args.notes);

    match &args.commands.unwrap() {
        Commands::Add(args) => {
            // println!("Username: {}", args.username);
            // println!("Password: {}", args.password);
        }
        Commands::Remove(args) => {}
        Commands::Update(args) => {}
        Commands::List(args) => {}
        Commands::Get(args) => {}
        Commands::Login(args) => {}
        Commands::Logout(args) => {}
        Commands::CreateUser(args) => {}
        Commands::RemoveUser(args) => {}
    }

    // TODO: Add clap for command line arguments
    // TODO: Add bcrypt for hashing passwords
    // TODO: Add file handling for storing passwords
}

/* Imp Notes:
 * For custom name of project -> cargo install --path . && pass
 */
