# Privacy Policy

**Last updated:** 2026-03-14

---

## The Short Version

Anya collects nothing. No data leaves your device. Ever.

---

## 1. What Data Anya Collects

**Nothing that leaves your device.**

Anya does not collect, transmit, aggregate, or sell any information about you, your
files, or how you use the software. There are no analytics events, no crash reports sent
to a server, no "phone home" behaviour of any kind.

This is not a default setting you can accidentally change. There is no server to send
data to.

---

## 2. What Is Stored Locally

Anya stores two categories of data on your machine, in a single SQLite database:

### Analysis results

When you analyse a file, Anya stores the analysis result in the local database. This
includes:

- The file's name and full path as it appeared on your filesystem at analysis time.
- The file's SHA-256, SHA-1, and MD5 hashes.
- The computed risk score and all analysis fields (sections, imports, entropy, strings,
  etc.) as JSON.
- The timestamp of when the analysis was run.

**The file itself is never copied, moved, or stored.** Only the results of reading it are
retained. If you delete the original file, Anya cannot recover it from the database.

### Settings

Anya stores your preferences in the same database:

- Theme (dark or light).
- Font size preference.
- Database file path (if you have changed it from the default).

No other settings exist.

### Where the database lives

| Platform | Default path |
|---|---|
| Windows | `%APPDATA%\com.anya.app\anya.db` |
| macOS | `~/Library/Application Support/com.anya.app/anya.db` |
| Linux | `~/.local/share/com.anya.app/anya.db` |

You can change the database location in Settings. You can inspect the database directly
with any SQLite browser.

---

## 3. File Handling

When you drop or open a file for analysis:

1. Anya reads the file from disk into memory.
2. It performs static analysis (hash computation, entropy calculation, PE/ELF parsing,
   string extraction).
3. The results are stored in the local SQLite database.
4. The file bytes are discarded from memory when analysis is complete.

**Anya never:**

- Copies the file to any other location on disk.
- Uploads the file or any portion of it to a remote server.
- Transmits the file hash to a lookup service (e.g. VirusTotal, NSRL, MalwareBazaar).
- Retains the file contents beyond the duration of a single analysis run.

If you want to submit a file to an external service for further analysis, that is your
choice to make manually, outside of Anya.

---

## 4. Network Activity

**Zero.** None.

Anya makes no outbound network connections of any kind. There are no:

- Telemetry pings.
- Automatic update checks.
- Licence validation requests.
- DNS lookups triggered by Anya's own code.
- Connections to threat intelligence feeds or hash databases.

This is not simply a configuration option that defaults to off. Network access is
disabled at the OS permission layer via Tauri's capability system. The application
manifest does not declare network permissions; the operating system will not grant them.
An attacker who compromises the Anya binary cannot use it as a network exfiltration
channel without also bypassing OS-level sandboxing.

You can verify this independently by running Anya under a network monitor (e.g. Wireshark,
Little Snitch, `ss -tp`). You will see no outbound connections.

---

## 5. Third-Party Services

**None are integrated by default.**

Anya does not integrate with VirusTotal, NSRL, MalwareBazaar, any threat intelligence
platform, or any other external service. No API keys are stored or used. No data is sent
to any of these services on your behalf.

If future versions of Anya add optional integrations with external services (e.g. an
opt-in VirusTotal hash lookup), the following will be true:

- The feature will be explicitly opt-in — disabled by default, requiring a deliberate
  action to enable.
- This privacy document will be updated before the feature ships.
- You will be clearly informed what data is sent, to whom, and under what conditions.

---

## 6. Deleting Your Data

To erase all data Anya has stored:

**Option 1 — Delete only the analysis history**
Open the SQLite database in any SQLite browser and drop the `analyses` table, or delete
rows individually.

**Option 2 — Delete everything**
Delete the database file from the path listed in Section 2. Anya will create a fresh,
empty database the next time it runs. Your preferences will be reset to defaults.

**Option 3 — Uninstall**
Uninstalling Anya removes the application binary. It does **not** automatically delete
the database file (standard behaviour for application data on all platforms). Delete the
database file manually after uninstalling if you want to remove all traces.

Anya leaves no registry entries (Windows), LaunchAgents (macOS), or systemd units
(Linux). Removing the binary and the database file leaves no other artefacts.

---

## 7. Children's Data

Anya is a security research and malware analysis tool intended for adult security
professionals, researchers, and students working under appropriate supervision. It is not
designed for use by or directed at children under 13 (or the applicable age of digital
consent in your jurisdiction). We do not knowingly collect data from children — but as
noted throughout this document, we do not collect data from anyone.

---

## 8. Changes to This Policy

If Anya's data practices change in a way that is material to your privacy, this document
will be updated and the "Last updated" date at the top will change. Significant changes
will also be noted in the CHANGELOG.

---

## 9. Contact

Questions about this privacy policy or Anya's data practices:

- **Email:** daniel@themalwarefiles.com
- **GitHub:** <https://github.com/elementmerc/anya/discussions>
