extern crate bytes;
extern crate rusoto_core;
extern crate rusoto_s3;

use std::collections::HashSet;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::StreamExt;
use rusoto_core::Region;
use rusoto_s3::{
    Delete, DeleteObjectRequest, DeleteObjectsRequest, GetObjectRequest,
    ObjectIdentifier, PutObjectRequest, S3Client, S3,
};
extern crate dotenv;

use crate::config::Config;

use super::Storage;

#[derive(Clone)]
pub struct S3Storage {
    bucket_name: String,
    s3_client: S3Client,
}

impl S3Storage {
    pub fn new(region: Region, bucket_name: &str) -> Self {
        let s3_client = S3Client::new(region);
        S3Storage {
            bucket_name: bucket_name.to_owned(),
            s3_client,
        }
    }

    pub fn from_config(config: Config) -> Self {
        let region = Region::Custom {
            name: config.aws_region_name,
            endpoint: config.aws_endpoint,
        };
        S3Storage::new(region, &config.aws_bucket_name)
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn upload(&self, filename: &str, data: &[u8]) -> Result<(), String> {
        let put_req = PutObjectRequest {
            bucket: self.bucket_name.to_string(),
            key: filename.to_string(),
            body: Some(data.to_vec().into()),
            ..Default::default()
        };

        match self.s3_client.put_object(put_req).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Could not upload file {}", e)),
        }
    }

    async fn download(&self, filename: &str) -> Result<Vec<u8>, String> {
        // Read data from a bucket
        let get_req = GetObjectRequest {
            bucket: self.bucket_name.to_string(),
            key: filename.to_string(),
            ..Default::default()
        };

        match self.s3_client.get_object(get_req).await {
            Ok(output) => {
                if let Some(body) = output.body {
                    let body_bytes = body.collect::<Vec<Result<Bytes, _>>>().await;
                    let data = body_bytes
                        .into_iter()
                        .filter_map(Result::ok)
                        .flatten()
                        .collect::<Vec<u8>>();
                    return Ok(data);
                } else {
                    Err("Body of file is None".to_string())
                }
            }
            Err(e) => Err(format!("Could not download file {}", e)),
        }
    }

    async fn delete(&self, filename: &str) -> Result<(), String> {
        // Delete data from a bucket
        let delete_req = DeleteObjectRequest {
            bucket: self.bucket_name.to_string(),
            key: filename.to_string(),
            ..Default::default()
        };

        match self.s3_client.delete_object(delete_req).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Could not delete file {}", e)),
        }
    }

    async fn batch_delete(&self, filenames: HashSet<String>) -> Result<(), String> {
        // Prepare the list of objects to delete
        let objects: Vec<ObjectIdentifier> = filenames
            .into_iter()
            .map(|filename| ObjectIdentifier {
                key: filename,
                ..Default::default()
            })
            .collect();

        let delete_req = DeleteObjectsRequest {
            bucket: self.bucket_name.to_string(),
            delete: Delete {
                objects,
                ..Default::default()
            },
            ..Default::default()
        };

        match self.s3_client.delete_objects(delete_req).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Could not batch delete files: {}", e)),
        }
    }
}
