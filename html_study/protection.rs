// ระบบป้องกัน Ransomware จริงๆ ที่คุณควรใช้
use std::path::Path;
use std::fs;
use std::io;
use log::{warn, error, info};
use sha2::{Sha256, Digest};
use serde_json::json;
use chrono::Utc;

pub struct RansomwareProtection {
    backup_dir: String,
    whitelist_extensions: Vec<String>,
    max_file_size: u64,
}

impl RansomwareProtection {
    pub fn new(backup_dir: &str) -> Self {
        Self {
            backup_dir: backup_dir.to_string(),
            whitelist_extensions: vec![
                "txt".to_string(),
                "jpg".to_string(),
                "png".to_string(),
                "pdf".to_string(),
                "doc".to_string(),
                "docx".to_string(),
            ],
            max_file_size: 10 * 1024 * 1024, // 10MB
        }
    }

    // 1. ตรวจสอบไฟล์ที่อัพโหลด
    pub fn validate_upload(&self, file_path: &Path, content: &[u8]) -> Result<(), String> {
        // ตรวจสอบนามสกุลไฟล์
        if let Some(ext) = file_path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if !self.whitelist_extensions.contains(&ext_str) {
                return Err(format!("File extension not allowed: {}", ext_str));
            }
        }

        // ตรวจสอบขนาดไฟล์
        if content.len() as u64 > self.max_file_size {
            return Err("File too large".to_string());
        }

        // ตรวจสอบ signature ไฟล์
        if self.detect_malicious_pattern(content) {
            return Err("File contains suspicious patterns".to_string());
        }

        Ok(())
    }

    // 2. ตรวจจับ pattern ransomware
    fn detect_malicious_pattern(&self, content: &[u8]) -> bool {
        let suspicious_strings = [
            "!README_DECRYPT", 
            ".encrypted",
            ".locked",
            ".crypt",
            "ransom",
            "bitcoin",
            "decrypt",
            "pay",
            "wallet"
        ];

        let content_str = String::from_utf8_lossy(content).to_lowercase();
        
        for pattern in &suspicious_strings {
            if content_str.contains(pattern) {
                warn!("Detected ransomware pattern: {}", pattern);
                return true;
            }
        }

        false
    }

    // 3. สร้าง backup ไฟล์
    pub fn create_backup(&self, file_path: &Path) -> io::Result<String> {
        let file_name = file_path.file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file name"))?
            .to_string_lossy();
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let backup_path = Path::new(&self.backup_dir)
            .join(format!("{}_{}", timestamp, file_name));
        
        if !Path::new(&self.backup_dir).exists() {
            fs::create_dir_all(&self.backup_dir)?;
        }

        fs::copy(file_path, &backup_path)?;
        
        info!("Backup created: {:?}", backup_path);
        Ok(backup_path.to_string_lossy().to_string())
    }

    // 4. ตรวจสอบ integrity ของไฟล์
    pub fn calculate_file_hash(&self, file_path: &Path) -> io::Result<String> {
        let content = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let result = hasher.finalize();
        
        Ok(format!("{:x}", result))
    }

    // 5. Monitor กิจกรรมไฟล์ที่น่าสงสัย
    pub fn monitor_file_activity(&self, path: &Path, operation: &str) {
        let suspicious_ops = vec!["mass_rename", "encrypt", "delete_many"];
        
        if suspicious_ops.contains(&operation) {
            error!("Suspicious file operation detected: {} on {:?}", operation, path);
            
            // Log to security system
            let log_entry = json!({
                "timestamp": Utc::now().to_rfc3339(),
                "event": "suspicious_file_operation",
                "path": path.to_string_lossy(),
                "operation": operation,
                "severity": "high"
            });
            
            // ใน production: ส่งแจ้งเตือน
            println!("SECURITY ALERT: {}", log_entry);
        }
    }
}

// File system watcher สำหรับตรวจจับ ransomware
pub struct FileSystemWatcher {
    watch_dirs: Vec<String>,
}

impl FileSystemWatcher {
    pub fn new(dirs: Vec<String>) -> Self {
        Self { watch_dirs: dirs }
    }

    pub fn start_monitoring(&self) {
        // ใน production ใช้ notify crate
        info!("Starting filesystem monitoring for: {:?}", self.watch_dirs);
    }
}