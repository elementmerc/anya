# Test Fixtures

Sample files for integration testing Anya.

## Current Fixtures

- `simple.exe` - Minimal .NET PE executable for testing PE parsing

## Creating More Test Fixtures

### ⚠️ NEVER Use Actual Malware

Test fixtures should be:
- ✅ Safe system executables
- ✅ Self-compiled programs
- ✅ Public PoC PE files
- ❌ **NEVER** real malware samples

---

## Method 1: Simple C Program

```c
// hello.c
#include <stdio.h>

int main() {
    printf("Test executable\n");
    return 0;
}
```

**Compile for Windows:**
```bash
# Linux/macOS (cross-compile)
x86_64-w64-mingw32-gcc hello.c -o test.exe

# Windows
cl hello.c /Fe:test.exe
```

**Compile for Linux:**
```bash
gcc hello.c -o test.elf
```

---

## Method 2: Copy System Files

**Windows:**
```bash
# Safe system executables
cp C:\Windows\System32\notepad.exe fixtures/notepad.exe
cp C:\Windows\System32\calc.exe fixtures/calc.exe
```

**Linux:**
```bash
# Safe binaries
cp /bin/ls fixtures/ls.elf
cp /usr/bin/cat fixtures/cat.elf
```

**macOS:**
```bash
cp /bin/ls fixtures/ls.bin
cp /usr/bin/grep fixtures/grep.bin
```

---

## Method 3: Download Safe Samples

### Corkami PE PoCs
```bash
git clone https://github.com/corkami/pocs
cp pocs/PE/tiny.exe fixtures/
```

### PE-bear Test Files
Download from: https://github.com/hasherezade/pe-bear-releases

---

## Using Fixtures in Tests

```rust
use std::path::PathBuf;

#[test]
fn test_analyse_pe() {
    let fixture = PathBuf::from("tests/fixtures/simple.exe");
    assert!(fixture.exists());
    
    // Your test code here
    let data = std::fs::read(&fixture).unwrap();
    // ...
}
```

---

## What Makes a Good Test Fixture?

### Good Fixtures:
- ✅ Small file size (<1MB)
- ✅ Known, documented structure
- ✅ Publicly available
- ✅ Safe to share in version control

### Bad Fixtures:
- ❌ Large files (>10MB)
- ❌ Proprietary software
- ❌ Actual malware
- ❌ Copyrighted binaries

---

## Recommended Test Files

### Minimal PE (already have)
- `simple.exe` - 6KB .NET executable

### Additional Suggestions:
- `packed.exe` - UPX-packed executable
- `signed.exe` - Code-signed executable  
- `dll_sample.dll` - Sample DLL with exports
- `driver.sys` - Kernel driver
- `corrupted.exe` - Intentionally malformed PE
- `high_entropy.bin` - High-entropy file (encrypted)

---

## Creating Specific Test Cases

### High Entropy File (Encrypted)
```bash
# Generate random data (simulates encryption)
dd if=/dev/urandom of=fixtures/high_entropy.bin bs=1024 count=10
```

### Corrupted PE
```bash
# Copy valid PE and corrupt it
cp fixtures/simple.exe fixtures/corrupted.exe
# Overwrite PE header
echo "GARBAGE" | dd of=fixtures/corrupted.exe bs=1 seek=60 conv=notrunc
```

### Packed Executable
```bash
# Download UPX
wget https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-amd64_linux.tar.xz
tar xf upx-4.0.2-amd64_linux.tar.xz

# Pack an executable
./upx-4.0.2-amd64_linux/upx -9 fixtures/test.exe -o fixtures/packed.exe
```

---

## File Naming Convention

Use descriptive names:
- `simple.exe` - Basic executable
- `packed_upx.exe` - UPX-packed
- `signed_cert.exe` - Code-signed
- `high_entropy.bin` - Encrypted/random
- `corrupted_header.exe` - Malformed
- `dll_with_exports.dll` - DLL sample

---

## Current Directory Structure

```
tests/
└── fixtures/
    ├── README.md (this file)
    └── simple.exe (minimal .NET PE)
```

## Adding More Fixtures

1. Create the file using one of the methods above
2. Copy to `tests/fixtures/`
3. **Keep files under 1MB** if possible
4. Document what makes it special

---

## Legal & Safety Notice

- ✅ You can use system executables for testing
- ✅ You can compile your own test programs
- ✅ You can use public PoC files
- ❌ Do NOT use pirated software
- ❌ Do NOT use actual malware
- ❌ Do NOT distribute copyrighted binaries

When in doubt, compile your own test files!