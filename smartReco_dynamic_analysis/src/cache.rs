use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::prelude::*;
use std::path::Path;

pub trait Cache {
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>>;
    fn save_without_recreate(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>>;
    fn load(&self, key: &str) -> Result<String, Box<dyn Error>>;
}

#[derive(Clone, Debug)]
pub struct FileSystemCache {
    pub file_path: String,
}

impl FileSystemCache {
    pub fn new(file_path: &str) -> FileSystemCache {
        let path = Path::new(file_path);
        if !path.exists() {
            fs::create_dir_all(path).unwrap();
        }

        FileSystemCache {
            file_path: file_path.to_string(),
        }
    }
}

impl Cache for FileSystemCache {
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let path = (self.file_path.clone() + "/" + key).to_lowercase();
        let parent_directory = Path::new(&path).parent().expect("Invalid file path");
        // println!("{:?}", parent_directory.ancestors());
        for parent in parent_directory.ancestors() {
            if let Some(path) = parent.to_str() {
                if !path.is_empty() && !path.ends_with(':') {
                    if !Path::new(path).exists() {
                        fs::create_dir(path)?;
                        // println!("Created folder: {}", path);
                    }
                }
            }
        }
        // write `value` to file `key`, create a new file if it doesn't exist
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;       
        file.write_all(value.as_bytes())?;
        Ok(())
    }

    fn save_without_recreate(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        // write `value` to file `key`, create a new file if it doesn't exist, or append if file exists
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open((self.file_path.clone() + "/" + key).to_lowercase())?;
        file.write_all(value.as_bytes())?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<String, Box<dyn Error>> {
        if !Path::exists(Path::new(((self.file_path.clone() + "/" + key).to_lowercase()).as_str())) {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Key not found",
            )));
        }

        let mut file = File::open((self.file_path.clone() + "/" + key).to_lowercase())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents)
    }
}
