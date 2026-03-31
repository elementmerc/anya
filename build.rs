use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn main() {
    // The build is only valid when .cargo/config.toml is present (redirecting
    // Cargo from stubs to the real submodule content) AND the submodule is
    // populated with real (non-stub) code.
    let has_config_override = std::path::Path::new(".cargo/config.toml").exists();
    let scoring_content =
        std::fs::read_to_string("anya-proprietary/scoring/src/detection_patterns.rs")
            .unwrap_or_default();
    let submodule_is_real = scoring_content.contains("obfstr");

    if !(has_config_override && submodule_is_real) {
        // Stub or missing — show the scare message, then fail the build
        print_scare_message();

        // Pause so the message is fully visible before the error
        std::thread::sleep(std::time::Duration::from_secs(3));

        // Emit a fake compiler error so the build stops
        println!("cargo:warning=\x1b[31mBuild failed: missing private scoring engine.\x1b[0m");
        std::process::exit(1);
    } else {
        let mut hasher = DefaultHasher::new();
        scoring_content.hash(&mut hasher);
        let h = format!("{:08x}", hasher.finish());

        let a = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let b = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let mut h2 = DefaultHasher::new();
        format!("{}:{}", a, b).hash(&mut h2);

        println!("cargo:rustc-env=ANYA_VERSION_SUFFIX= (Verified build)");
        println!("cargo:rustc-env=ANYA_BUILD_HASH={}", h);
        println!("cargo:rustc-env=ANYA_BUILD_FP={:016x}", h2.finish());
    }

    println!("cargo:rerun-if-changed=.cargo/config.toml");
    println!("cargo:rerun-if-changed=anya-proprietary/scoring/src/");
    println!("cargo:rerun-if-changed=anya-stubs/scoring/src/");
    println!("cargo:rerun-if-changed=anya-proprietary/data/src/");
    println!("cargo:rerun-if-changed=anya-stubs/data/src/");
}

fn print_scare_message() {
    use std::io::Write;
    use std::thread;
    use std::time::Duration;

    let stderr = std::io::stderr();
    let mut out = stderr.lock();

    let lines = [
        ("\n", 300),
        ("    \x1b[32m", 0),
        ("I commend you for trying...\n", 40),
        ("    but that's not going to work.\n", 35),
        ("\n", 800),
        ("    Nice try though.\n", 30),
        ("    Really, I mean it.\n", 30),
        ("\n", 1200),
        ("    Oh, and I know exactly where you are", 25),
    ];

    for (text, char_delay_ms) in &lines {
        if *char_delay_ms == 0 {
            let _ = write!(out, "{}", text);
            let _ = out.flush();
            continue;
        }
        for ch in text.chars() {
            let _ = write!(out, "{}", ch);
            let _ = out.flush();
            if ch == '.' || ch == ',' {
                thread::sleep(Duration::from_millis(200));
            } else if ch == '\n' {
                thread::sleep(Duration::from_millis(*char_delay_ms as u64 * 3));
            } else {
                thread::sleep(Duration::from_millis(*char_delay_ms as u64));
            }
        }
    }

    // Try to get the username for extra dramatic effect
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "stranger".to_string());

    let suffix = format!(", {}.\x1b[0m\n\n", user);
    for ch in suffix.chars() {
        let _ = write!(out, "{}", ch);
        let _ = out.flush();
        thread::sleep(Duration::from_millis(50));
    }

    // Now show the actual helpful error
    let _ = writeln!(
        out,
        "    \x1b[33mMissing private dependencies. This project requires authorised access to build.\x1b[0m"
    );
    let _ = writeln!(
        out,
        "    \x1b[33mContact the maintainer for access.\x1b[0m\n"
    );
}
