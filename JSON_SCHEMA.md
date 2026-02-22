# JSON Output

Anya supports JSON output for integration with automation tools, databases, and security platforms.

## Basic Usage

```bash
# Standard human-readable output
anya --file malware.exe

# Machine-readable JSON output
anya --file malware.exe --json

# Pretty-print with jq
anya --file malware.exe --json | jq '.'

# Extract specific fields
anya --file malware.exe --json | jq '.hashes.sha256'
```

## JSON Schema

### Top-Level Structure

```json
{
  "file_info": { ... },      // File metadata
  "hashes": { ... },         // MD5, SHA1, SHA256
  "entropy": { ... },        // Shannon entropy analysis
  "strings": { ... },        // Extracted strings
  "file_format": "string",   // Detected format
  "pe_analysis": { ... }     // PE-specific analysis (optional)
}
```

### Complete Example

```json
{
  "file_info": {
    "path": "malware.exe",
    "size_bytes": 524288,
    "size_kb": 512.0,
    "extension": "exe"
  },
  "hashes": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "entropy": {
    "value": 7.8,
    "category": "Very high - likely encrypted or packed",
    "is_suspicious": true
  },
  "strings": {
    "min_length": 4,
    "total_count": 142,
    "samples": ["http://example.com", "kernel32.dll", ...],
    "sample_count": 50
  },
  "file_format": "Windows PE",
  "pe_analysis": {
    "architecture": "PE32+ (64-bit)",
    "is_64bit": true,
    "image_base": "0x140000000",
    "entry_point": "0x1000",
    "file_type": "EXE",
    "security": {
      "aslr_enabled": true,
      "dep_enabled": true
    },
    "sections": [
      {
        "name": ".text",
        "virtual_size": 4096,
        "virtual_address": "0x1000",
        "raw_size": 4096,
        "entropy": 6.2,
        "is_suspicious": false,
        "is_wx": false
      }
    ],
    "imports": {
      "dll_count": 5,
      "total_imports": 42,
      "suspicious_api_count": 3,
      "suspicious_apis": [
        {
          "name": "CreateRemoteThread",
          "category": "Code Injection"
        }
      ],
      "libraries": ["kernel32.dll", "ntdll.dll"]
    },
    "exports": {
      "total_count": 12,
      "samples": [
        {
          "name": "DllMain",
          "rva": "0x00001000"
        }
      ]
    }
  }
}
```

## Integration Examples

### Extract Hash for VirusTotal Lookup

```bash
SHA256=$(anya --file malware.exe --json | jq -r '.hashes.sha256')
curl "https://www.virustotal.com/api/v3/files/$SHA256" \
  -H "x-apikey: $VT_API_KEY"
```

### Store in Database (Python)

```python
import subprocess
import json
from pymongo import MongoClient

# Analyse file
result = subprocess.run(['anya', '--file', 'malware.exe', '--json'],
                       capture_output=True, text=True)
data = json.loads(result.stdout)

# Store in MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client.malware_analysis
db.samples.insert_one(data)
```

### Batch Processing

```bash
# Analyse all files and save results
for file in samples/*.exe; do
    anya --file "$file" --json >> results.jsonl
done

# Find suspicious files
cat results.jsonl | jq 'select(.entropy.is_suspicious == true)'
```

### Check for Specific Threats

```bash
# Find files with code injection APIs
anya --file *.exe --json | \
  jq 'select(.pe_analysis.imports.suspicious_apis[].category == "Code Injection")'

# Files with disabled ASLR
anya --file *.dll --json | \
  jq 'select(.pe_analysis.security.aslr_enabled == false)'
```

## Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `file_info.path` | string | File path |
| `file_info.size_bytes` | integer | Size in bytes |
| `file_info.size_kb` | float | Size in kilobytes |
| `hashes.md5` | string | MD5 hash (hex) |
| `hashes.sha1` | string | SHA1 hash (hex) |
| `hashes.sha256` | string | SHA256 hash (hex) |
| `entropy.value` | float | Shannon entropy (0.0-8.0) |
| `entropy.is_suspicious` | boolean | High entropy flag (>7.5) |
| `strings.total_count` | integer | Total strings found |
| `pe_analysis.security.aslr_enabled` | boolean | ASLR status |
| `pe_analysis.security.dep_enabled` | boolean | DEP/NX status |
| `pe_analysis.imports.suspicious_api_count` | integer | Suspicious API count |