//! Upload credentials must be configured independently of event credentials.
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Receiver {
    child: Child,
    schemas: std::path::PathBuf,
}
impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.schemas);
    }
}

#[test]
fn upload_authorization_never_inherits_the_event_token() {
    for configured in [false, true] {
        let schemas = std::env::temp_dir().join(format!(
            "rust-elicitation-auth-{}-{configured}",
            std::process::id()
        ));
        fs::create_dir_all(&schemas).unwrap();
        let bundle: Vec<Value> = serde_json::from_str(include_str!("../src/schemas.json")).unwrap();
        for schema in bundle {
            let name = schema["$id"].as_str().unwrap().rsplit('/').next().unwrap();
            fs::write(schemas.join(name), serde_json::to_vec(&schema).unwrap()).unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_elicitation"));
        command
            .args(["server", schemas.to_str().unwrap(), "test-principal"])
            .env("AHP_ELICITATION_TOKEN", "TEST-EVENT-TOKEN")
            .env_remove("AHP_ELICITATION_UPLOAD_TOKEN")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if configured {
            command.env("AHP_ELICITATION_UPLOAD_TOKEN", "TEST-UPLOAD-TOKEN");
        }
        let mut receiver = Receiver {
            child: command.spawn().unwrap(),
            schemas,
        };
        let stdout = receiver.child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let line = BufReader::new(stdout).lines().next();
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(Duration::from_secs(15))
            .unwrap()
            .unwrap()
            .unwrap();
        let ready: Value = serde_json::from_str(&line).unwrap();
        let endpoint = format!("{}/upload", ready["endpoint"].as_str().unwrap());
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        for (token, expected) in [
            ("TEST-EVENT-TOKEN", 401),
            ("TEST-UPLOAD-TOKEN", if configured { 201 } else { 401 }),
        ] {
            let response = client
                .post(&endpoint)
                .bearer_auth(token)
                .header("Content-Type", "application/octet-stream")
                .header(
                    "AHP-Content-SHA256",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
                .body(Vec::new())
                .send()
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
        }
    }
}
