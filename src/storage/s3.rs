extern crate bytes;
extern crate rusoto_core;
extern crate rusoto_s3;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::StreamExt;
use rusoto_core::Region;
use rusoto_s3::{GetObjectRequest, PutObjectRequest, S3Client, S3};
extern crate dotenv;

use super::Storage;

pub struct S3Storage {
    bucket_name: String,
    s3_client: S3Client,
}

impl S3Storage {
    pub fn new(region: Region, bucket_name: String) -> Self {
        let s3_client = S3Client::new(region);
        S3Storage {
            bucket_name,
            s3_client,
        }
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn upload(&self, filename: &str, data: &[u8]) -> Result<(), String> {
        todo!()
    }

    async fn download(&self, filename: &str) -> Result<Vec<u8>, String> {
        todo!()
    }

    async fn delete(&self, filename: &str) -> Result<(), String> {
        todo!()
    }

    async fn list(&self) -> Result<Vec<String>, String> {
        todo!()
    }
}
