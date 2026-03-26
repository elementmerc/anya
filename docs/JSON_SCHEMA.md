# JSON Output

Anya supports JSON output for integration with automation tools, databases, and security platforms.

JSON output is available from the CLI. The desktop GUI stores the same structure in the local SQLite database (`result_json` column).

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
  "file_info": { ... },           // File metadata + MIME type
  "hashes": { ... },              // MD5, SHA1, SHA256, TLSH
  "entropy": { ... },             // Shannon entropy + confidence
  "strings": { ... },             // Extracted strings with classification
  "file_format": "string",        // Detected format
  "pe_analysis": { ... },         // PE-specific analysis (optional)
  "elf_analysis": { ... },        // ELF-specific analysis (optional)
  "file_type_mismatch": { ... },  // Extension vs magic bytes (optional)
  "ioc_summary": { ... },         // IOC indicators found (optional)
  "mach_analysis": { ... },       // Mach-O-specific analysis (optional)
  "pdf_analysis": { ... },        // PDF dangerous object detection (optional)
  "office_analysis": { ... },     // Office macro/embedded object detection (optional)
  "verdict_summary": "string",    // e.g. "MALICIOUS — 2 critical, 1 high"
  "top_findings": [ ... ]         // Top N findings by confidence
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
    "value": "<value> (above internal packed threshold)",
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
      "suspicious_api_count": "<count>",
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

> **Note:** Example values are illustrative. Actual detection thresholds and scoring logic are determined internally.

## Case YAML Schema

When using `--case <name>` or the GUI "Save to Case" feature, results are
saved to a case directory:

```yaml
case:
  name: "operation-nightfall"
  created: "2026-03-16T14:32:00Z"
  updated: "2026-03-16T15:10:00Z"
  status: "open"

files:
  - path: "/samples/suspicious.exe"
    sha256: "abc123..."
    verdict: "MALICIOUS"
    analysed_at: "2026-03-16T14:32:00Z"
    report: "reports/suspicious.exe_2026-03-16T14-32-00.json"
```

Each file's `report` field points to a full JSON analysis result stored
in the `reports/` subdirectory.

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
| `mach_analysis.architecture` | string | CPU architecture (x86_64, arm64, etc.) |
| `mach_analysis.dylib_imports` | string[] | Imported dynamic libraries |
| `mach_analysis.has_code_signature` | boolean | Code signature present |
| `mach_analysis.pie_enabled` | boolean | Position-independent executable |
| `mach_analysis.nx_enabled` | boolean | Non-executable stack |
| `pdf_analysis.dangerous_objects` | string[] | Dangerous PDF objects found (/JS, /Launch, etc.) |
| `pdf_analysis.risk_indicators` | string[] | Plain-English risk descriptions |
| `office_analysis.has_macros` | boolean | VBA macros present |
| `office_analysis.has_embedded_objects` | boolean | Embedded objects found |
| `office_analysis.has_external_links` | boolean | External URL references |
| `strings.suppressed_reason` | string? | Why string extraction was skipped (e.g. image files) |