use rusoto_core::Region;

pub struct S3 {
    region: Region,
    bucket_name: String,
}

impl S3 {
    pub fn new(region: Region, bucket_name: String) -> Self {
        S3 {
            region,
            bucket_name,
        }
    }
}
