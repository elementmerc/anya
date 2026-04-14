use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn main() {
    // A real build requires two things:
    //   1. .cargo/config.toml exists (so cargo is redirecting the anya-scoring
    //      and anya-data stub crates to a real local impl via path override).
    //   2. The scoring crate that ends up in the dep graph emits a "real" token
    //      via its own build.rs, forwarded to us as DEP_SCORING_IMPL_TOKEN.
    //      The anya-stubs/scoring crate declares no `links` value so its
    //      presence in the graph leaves DEP_SCORING_IMPL_* unset, and we fall
    //      through to the scare message.
    let has_config_override = std::path::Path::new(".cargo/config.toml").exists();
    let impl_token = std::env::var("DEP_SCORING_IMPL_TOKEN").unwrap_or_default();
    let impl_hash = std::env::var("DEP_SCORING_IMPL_HASH").unwrap_or_default();
    let impl_is_real = impl_token == "real";

    if !(has_config_override && impl_is_real) {
        // Stub or missing — show the scare message, then fail the build
        print_scare_message();

        // Pause so the message is fully visible before the error
        std::thread::sleep(std::time::Duration::from_secs(3));

        // Emit a fake compiler error so the build stops
        println!("cargo:warning=\x1b[31mBuild failed: missing private scoring engine.\x1b[0m");
        std::process::exit(1);
    } else {
        // Host fingerprint: hash of username + hostname, used to distinguish
        // builds across machines. Pure local signal, never transmitted.
        let a = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let b = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let mut h2 = DefaultHasher::new();
        format!("{}:{}", a, b).hash(&mut h2);

        println!("cargo:rustc-env=ANYA_VERSION_SUFFIX= (Verified build)");
        println!("cargo:rustc-env=ANYA_BUILD_HASH={impl_hash}");
        println!("cargo:rustc-env=ANYA_BUILD_FP={:016x}", h2.finish());
    }

    println!("cargo:rerun-if-changed=.cargo/config.toml");
    println!("cargo:rerun-if-env-changed=DEP_SCORING_IMPL_TOKEN");
    println!("cargo:rerun-if-env-changed=DEP_SCORING_IMPL_HASH");
    println!("cargo:rerun-if-changed=anya-stubs/scoring/src/");
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
