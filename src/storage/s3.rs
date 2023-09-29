extern crate bytes;
extern crate rusoto_core;
extern crate rusoto_s3;

use std::collections::HashSet;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::StreamExt;
use rusoto_core::Region;
use rusoto_s3::{
    DeleteObjectRequest, GetObjectRequest, ListObjectsV2Request, PutObjectRequest, S3Client, S3,
};
extern crate dotenv;

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
                    Err(format!("Body of file is None",))
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

    async fn list(&self) -> Result<Vec<String>, String> {
        // List all files in a bucket
        let list_req = ListObjectsV2Request {
            bucket: self.bucket_name.to_string(),
            ..Default::default()
        };

        match self.s3_client.list_objects_v2(list_req).await {
            Ok(output) => {
                if let Some(objects) = output.contents {
                    let mut filenames = Vec::new();
                    for object in objects {
                        if let Some(key) = object.key {
                            filenames.push(key);
                        }
                    }
                    Ok(filenames)
                } else {
                    Err(format!("Could not list files"))
                }
            }
            Err(e) => Err(format!("Could not list files {}", e)),
        }
    }

    async fn size_of(&self, encrypted_filenames: HashSet<String>) -> Result<i64, String> {
        // List all files in a bucket
        let list_req = ListObjectsV2Request {
            bucket: self.bucket_name.to_string(),
            ..Default::default()
        };

        let mut total_size = 0;

        match self.s3_client.list_objects_v2(list_req).await {
            Ok(output) => {
                if let Some(objects) = output.contents {
                    for object in objects {
                        if let Some(key) = object.key {
                            if encrypted_filenames.contains(&key) {
                                let size = object.size.unwrap_or(0);
                                total_size += size;
                            }
                        }
                    }
                    Ok(total_size)
                } else {
                    return Err(format!("Could not get file size"));
                }
            }
            Err(e) => return Err(format!("Could not get file size {}", e)),
        }
    }
}
