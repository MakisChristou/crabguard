use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    rc::Rc,
    time::Instant,
};

use crate::{
    config::Config,
    crypto::{self, CounterNonceSequence},
    filename_handler::FileNameHandler,
    storage::Storage,
    utils, CHUNK_SIZE, MAX_RETRIES,
};
use ring::{aead::NONCE_LEN, error::Unspecified};
use sha2::{Digest, Sha256};

pub struct CommandHandler {
    storage: Rc<dyn Storage>,
    filename_handler: FileNameHandler,
    config: Config,
}

impl CommandHandler {
    pub fn new(
        storage: Rc<dyn Storage>,
        filename_handler: FileNameHandler,
        config: Config,
    ) -> Self {
        CommandHandler {
            storage,
            filename_handler,
            config,
        }
    }

    async fn encrypt_and_upload_data_chunk(
        data: &Vec<u8>,
        plaintext_filename: &str,
        key_bytes: Vec<u8>,
        storage: Rc<dyn Storage>,
    ) -> Result<(), Unspecified> {
        let nonce_sequence = CounterNonceSequence::new_random();
        let starting_value = nonce_sequence.0.to_vec();

        let cypher_text_with_tag =
            crypto::encrypt(data.to_owned(), key_bytes.clone(), nonce_sequence)?;

        // Prepend the nonce on the ciphertext
        let mut data_to_store = starting_value;
        data_to_store.extend_from_slice(&cypher_text_with_tag);

        let hashed_filename = hex::encode(Sha256::digest(plaintext_filename)).to_string();

        let mut retries = 0;

        while retries < MAX_RETRIES {
            match storage.upload(&hashed_filename, &data_to_store).await {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    println!("{}, retrying...", e);
                    retries += 1;
                    continue;
                }
            }
        }

        Err(Unspecified)
    }

    async fn download_and_decrypt_chunk(
        plaintext_filename: &str,
        key_bytes: Vec<u8>,
        storage: Rc<dyn Storage>,
    ) -> Result<Vec<u8>, Unspecified> {
        let file_contents = storage
            .download(&hex::encode(Sha256::digest(plaintext_filename)).to_string())
            .await
            .map_err(|_| Unspecified)?;

        // Extract nonce from first 12 bytes of file
        let starting_value = &file_contents[..NONCE_LEN];
        let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
        let nonce_sequence = CounterNonceSequence::new(nonce_array);

        // Extract actual cyphertext
        let cypher_text_with_tag = &file_contents[NONCE_LEN..];

        let decrypted_data =
            crypto::decrypt(cypher_text_with_tag.to_vec(), key_bytes, nonce_sequence)?;

        Ok(decrypted_data)
    }

    pub async fn handle_upload(&mut self, file_path: &str) -> Result<(), Unspecified> {
        let path = Path::new(file_path);
        let mut file = File::open(file_path).unwrap();

        if let Some(file_name) = path.file_name() {
            let plaintext_filename = file_name.to_str().unwrap();

            let file_len = file.metadata().unwrap().len() as usize;
            let total_chunks = (file_len + CHUNK_SIZE - 1) / CHUNK_SIZE;

            // Get the number of chunks assosiated with this file that were previously uploaded
            let associated_filenames = self
                .filename_handler
                .get_all_filenames_of(plaintext_filename, self.config.key_bytes.clone());

            let mut remote_chunks = associated_filenames.len();

            if remote_chunks > total_chunks {
                self.handle_delete(plaintext_filename).await?;
                remote_chunks = 0;
            }

            if remote_chunks == total_chunks {
                println!("File {} already uploaded!", plaintext_filename);
                let answer = utils::prompt_yes_no("Do you want to replace it? [y|n]").unwrap();

                if answer {
                    self.handle_delete(plaintext_filename).await?;
                    remote_chunks = 0;
                } else {
                    return Ok(());
                }
            }

            // Initialize the progress bar
            let pb = utils::create_progress_bar(total_chunks as u64);
            let start_time = Instant::now();

            // Move progress bar and file pointer accordingly
            pb.inc((remote_chunks * CHUNK_SIZE) as u64);
            file.seek(SeekFrom::Start((remote_chunks * CHUNK_SIZE) as u64))
                .unwrap();

            let mut chunks_sent_so_far = 0;

            for chunk in remote_chunks..total_chunks {
                let mut chunk_data = vec![0; CHUNK_SIZE];
                let bytes_read = file.read(&mut chunk_data).unwrap();
                chunk_data.truncate(bytes_read); // Handle last chunk

                Self::encrypt_and_upload_data_chunk(
                    &chunk_data,
                    &format!("{}_{}", plaintext_filename, chunk),
                    self.config.key_bytes.clone(),
                    Rc::clone(&self.storage),
                )
                .await?;

                self.filename_handler
                    .add_name_to_hashmap(
                        &format!("{}_{}", plaintext_filename, chunk),
                        self.config.key_bytes.clone(),
                        chunk_data.len(),
                    )
                    .await?;

                chunks_sent_so_far += 1;
                utils::update_progress_bar(&pb, chunks_sent_so_far, &start_time);
            }

            pb.finish_with_message("upload complete");
        } else {
            panic!("Path given does not contain filename");
        }

        Ok(())
    }

    pub async fn handle_download(&mut self, file_name: &str) -> Result<(), Unspecified> {
        let path = Path::new(file_name);

        if let Some(file_name) = path.file_name() {
            let plaintext_filename = file_name.to_str().unwrap();

            let associated_filenames = self
                .filename_handler
                .get_all_filenames_of(plaintext_filename, self.config.key_bytes.clone());

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(file_name)
                .unwrap();

            // Start from the last stored chunk
            let mut current_chunk = (file.metadata().unwrap().len() / CHUNK_SIZE as u64) as usize;

            let mut total_size = 0;
            for assosiated_filename in associated_filenames {
                let hashmap_entry = self.filename_handler.get(&assosiated_filename).unwrap();
                total_size += hashmap_entry.size;
            }

            let total_chunks = (total_size / CHUNK_SIZE) as i64;

            // Initialize the progress bar
            let pb = utils::create_progress_bar(total_chunks.try_into().unwrap());
            let start_time = Instant::now();
            pb.inc((current_chunk * CHUNK_SIZE) as u64);
            let mut chunks_so_far = 0;

            loop {
                match Self::download_and_decrypt_chunk(
                    &format!("{}_{}", plaintext_filename, current_chunk),
                    self.config.key_bytes.clone(),
                    Rc::clone(&self.storage),
                )
                .await
                {
                    Ok(decrypted_data) => {
                        file.write_all(&decrypted_data).unwrap();
                        utils::update_progress_bar(&pb, chunks_so_far, &start_time);
                    }
                    Err(e) => {
                        if current_chunk != 0 {
                            return Ok(());
                        } else {
                            panic!("{}", e);
                        }
                    }
                }
                current_chunk += 1;
                chunks_so_far += 1;
            }
        } else {
            panic!("Path given does not contain filename");
        }
    }

    pub async fn handle_delete(&mut self, file_name: &str) -> Result<(), Unspecified> {
        let path = Path::new(file_name);
        if let Some(file_name) = path.file_name() {
            let plaintext_filename = file_name.to_str().unwrap();
            let associated_filenames = self
                .filename_handler
                .get_all_filenames_of(plaintext_filename, self.config.key_bytes.clone());

            self.storage
                .batch_delete(associated_filenames.clone())
                .await
                .unwrap();
            self.filename_handler
                .remove_names_from_hashmap(associated_filenames)
                .await?;
        } else {
            panic!("Path given does not contain filename");
        }
        Ok(())
    }

    pub async fn handle_list(&self) -> Result<(), Unspecified> {
        let unique_file_names = self
            .filename_handler
            .get_unique_filenames(self.config.key_bytes.clone());

        if unique_file_names.is_empty() {
            println!("Bucket is empty!");
        } else {
            for filename in unique_file_names {
                println!("{}", filename);
            }
        }
        Ok(())
    }
}
