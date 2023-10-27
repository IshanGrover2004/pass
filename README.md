

# pass
pass is a command-line tool for generating and managing passwords. It is easy-to-use CLI tool.

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
- **Encryption**: All stored passwords are encrypted for enhanced security.
- **Command-Line Interface**: A user-friendly and scriptable CLI for quick access to your passwords.

### Installation
To install `pass`, you need to have Rust and Cargo (Rust's package manager) installed. Then, you can use Cargo to install `pass` as follows:

```shell
cargo install pass
```
or 
```shell
git clone https://github.com/tanveerraza789/pass && cd pass
cargo install --path .
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
  help           Print all options & subcommands

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Usage
TODO: Usage of commands images

### How it works
TODO: Storage flowchart

### Contributing

Contributions are welcome! If you’d like to contribute, please feel free to open an issue or submit a pull request. Checkout our [CONTRIBUTING](https://github.com/tanveerraza789/pass/blob/main/CONTRIBUTING.md) file for details on how to contribute.

### License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/tanveerraza789/pass/blob/main/LICENSE) file for details.
