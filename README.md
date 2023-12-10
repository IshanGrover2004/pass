# pass_rs

Pass is a simple and secure password manager written in Rust, designed to help you store and manage your passwords with ease. It offers features like password generation, encryption, and a user-friendly command-line interface.

## Table of Contents

- [Project Features](#project-features)
- [Installation](#installation)
- [CLI Commands](#cli-commands)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)

### Project Features

- **Password Management**: Store and organize your passwords securely.
- **Password Generation**: Easily create strong and random passwords with customizable options.
- **Encryption**: All stored passwords are encrypted for enhanced security. Encryption is done using `XChaCha20-Poly1305`.
- **Command-Line Interface**: A user-friendly and scriptable CLI for quick access to your passwords.

### Installation

To install `pass`, you need to have Rust and Cargo (Rust's package manager) installed. Then, you can use Cargo to install `pass` as follows:

```shell
cargo install --git https://github.com/tanveerraza789/pass.git
```

### CLI Commands

```rust
Subcommands:
  init           Initialize the pass
  change-master  Change Master password
  add            Make a new password
  remove         Remove a password
  update         Update a password
  list           List all made password
  get            Get a password
  gen            Generate a password
  help           Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Usage

![Usage](https://github.com/atamakahere-git/pass/blob/master/docs/usage.gif)

### How it works

![storage of passwords](./docs/pass_store_flow.png)

### Contributing

Contributions are welcome! If you’d like to contribute, please feel free to open an issue or submit a pull request. Checkout our [CONTRIBUTING](./CONTRIBUTING.md) file for details on how to contribute.

### License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/tanveerraza789/pass/blob/main/LICENSE) file for details.
