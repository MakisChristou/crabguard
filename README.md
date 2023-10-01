🦀🔒 crabguard: A cli tool for end-to-end encryption for remote and local storage

[![crates.io](https://buildstats.info/crate/crabguard)](https://crates.io/crates/crabguard)

## Features
- Encrypted upload, download and delete operations on Amazon S3 storage
- AES-GCM symmetric encryption with random 96-bit nonce
- Hashed filenames using sha256
- File chuking (currently chunk size is hardcoded to 1MB)
- Resume upload when interuppted

## Getting started
Create a `.env` file like so

```
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION_NAME=us-west-004
AWS_ENDPOINT=s3.us-west-004.backblazeb2.com
AWS_BUCKET_NAME=testbucket
```

When the upload command is run a new key will be generated and stored in your `.env` file. It goes without saying that you should backup this key. If you lose it you can't decrypt your files or even the filenames. 

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
