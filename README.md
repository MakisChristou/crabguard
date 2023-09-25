🦀🔒 crabguard: A cli tool for end-to-end encryption for remote and local storage

## Features
- Encrypted CRUD on Amazon S3 storage
- AES-GCM symmetric encryption with random 96-bit nonce
- Encrypted filenames
- File chuking

## Common Commands

```bash
cargo r --release -- upload ~/Downloads/23-08-11\ 11-35-15\ 3555.jpg
```

```bash
cargo r --release -- download 23-08-11\ 11-35-15\ 3555.jpg
```

```bash
cargo r --release -- delete 23-08-11\ 11-35-15\ 3555.jpg
```

```bash
cargo r --release -- list
```
