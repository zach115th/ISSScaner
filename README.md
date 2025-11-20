Here’s a README you can drop straight into `README.md` for this script. You can tweak the repo name / author bits as you like.

---

# IIS Web Attack Log Scanner

PowerShell 7 script to recursively scan IIS logs for signs of:

* **SQL injection**
* **Web shell activity**
* **File inclusion / LFI / RFI**

It’s built for **DFIR at scale** – think tens of thousands of log files and tens of gigabytes of data – using:

* `ForEach-Object -Parallel` (PowerShell 7+)
* Streaming reads via `[System.IO.File]::ReadLines()`
* Regex-based signatures for common web attacks

---

## Features

* 🔎 **Recursive scan** of a root directory for IIS log files (`*.log` by default)
* ⚡ **Parallel processing** with configurable `ThrottleLimit`
* 🧪 **Attack detection categories**

  * `SQLi` – SQL injection and related DB-enumeration patterns
  * `WebShell` – webshell-like file names, RCE-ish commands, recon commands
  * `FileInclusion` – LFI/RFI patterns, directory traversal, remote includes
* 🕒 **Time-scoped analysis** with `-StartDate` / `-EndDate` filtering on file `LastWriteTime`
* 📄 **CSV output** with useful fields per hit:

  * File, LineNumber, Type, Date, Time, ClientIP, UriStem, UriQuery, Status, TimeTaken, RawLine

---

## Requirements

* **PowerShell 7+** (for `ForEach-Object -Parallel`)
* Windows (designed for IIS W3C logs, but will happily read any text logs)
* Sufficient permissions to read the log directory

---

## Usage

### Basic scan

Scan all IIS logs under a root directory and write hits to `WebAttackHits.csv`:

```powershell
pwsh.exe -File .\scanner.ps1 `
  -RootPath "E:\CDFA\2025-11-19T222507_Kape_Mercury\C\inetpub\logs\LogFiles"
```

### Custom output path

```powershell
pwsh.exe -File .\scanner.ps1 `
  -RootPath "E:\CDFA\...\LogFiles" `
  -OutputCsv ".\iis_web_attacks.csv"
```

### Parallelism (ThrottleLimit)

Use more runspaces to speed up scanning on multi-core systems:

```powershell
pwsh.exe -File .\scanner.ps1 `
  -RootPath "E:\CDFA\...\LogFiles" `
  -ThrottleLimit 24 `
  -OutputCsv ".\iis_web_attacks.csv"
```

> **Tip:**
>
> * On SSD/NVMe, a higher `ThrottleLimit` (e.g. 16–32) can help.
> * On spinning disks or slow network shares, too many workers can cause I/O thrashing.

### Date-filtered scan

Filter files by `LastWriteTime` to focus on a specific incident window.

**Only logs modified on or after a date:**

```powershell
pwsh.exe -File .\scanner.ps1 `
  -RootPath "E:\CDFA\...\LogFiles" `
  -StartDate "2025-11-18"
```

**Specific time window:**

```powershell
pwsh.exe -File .\scanner.ps1 `
  -RootPath "E:\CDFA\...\LogFiles" `
  -StartDate "2025-11-18T00:00:00" `
  -EndDate   "2025-11-19T23:59:59" `
  -OutputCsv ".\iis_web_attacks_incident.csv"
```

### Verbose mode (debug / tuning)

See which files are being scanned and how many remain after filters:

```powershell
pwsh.exe -File .\scanner.ps1 `
  -RootPath "E:\CDFA\...\LogFiles" `
  -ThrottleLimit 12 `
  -VerboseMode
```

---

## Parameters

| Parameter           | Required | Type       | Description                                                                  |
| ------------------- | -------- | ---------- | ---------------------------------------------------------------------------- |
| `RootPath`          | ✅        | `string`   | Root directory to recursively search for log files.                          |
| `OutputCsv`         | ❌        | `string`   | Output CSV path. Default: `WebAttackHits.csv`.                               |
| `IncludeExtensions` | ❌        | `string[]` | File patterns to include (name-based). Default: `*.log`.                     |
| `ThrottleLimit`     | ❌        | `int`      | Number of parallel runspaces to use. Default: `8`.                           |
| `StartDate`         | ❌        | `datetime` | Only scan files with `LastWriteTime >= StartDate`.                           |
| `EndDate`           | ❌        | `datetime` | Only scan files with `LastWriteTime <= EndDate`.                             |
| `VerboseMode`       | ❌        | `switch`   | Enables verbose logging (`Write-Verbose`). Helpful for tuning and debugging. |

---

## Detection Logic

The script operates line-by-line over IIS W3C logs using `[System.IO.File]::ReadLines()`. For each non-comment line:

1. Matches against a **combined regex** (`$CombinedPattern`) to quickly skip non-interesting lines.
2. If it passes the gate, the line is classified into one of:

   * `SQLi`
   * `WebShell`
   * `FileInclusion`
   * `Unknown` (matched combined pattern but not any category-specific pattern)
3. If a `#Fields:` header is seen, the script builds a field map so it can extract:

   * `date`, `time`, `c-ip`, `cs-uri-stem`, `cs-uri-query`, `sc-status`, `time-taken` (if present)
4. A `PSCustomObject` is created per hit and later exported to CSV.

### SQL Injection (`SQLi`)

Heuristics include (case-insensitive):

* `UNION SELECT`
* `SELECT ... FROM`
* `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`, `DROP TABLE/DATABASE`
* `EXEC` / `xp_cmdshell` / generic `exec sp_/xp_`
* `WAITFOR DELAY`, `SLEEP(`
* `information_schema`, `sysobjects`, `sys.tables`
* Stacked queries via `;` or `%3B` followed by SQL verbs

### Web Shell Activity (`WebShell`)

Patterns include:

* Suspicious shell-like script names:

  * `cmd.php`, `shell.asp`, `webshell.aspx`, `c99.php`, `r57.php`, etc.
* Common admin/single-file tools:

  * `phpinfo.php`, `adminer.php`
* Query-string parameters indicating RCE / shell-like usage:

  * `cmd=`, `exec=`, `command=`, `shell=`, `upload=`, `file=`, `dir=`, `run=`
* Use of Windows tools with flags:

  * `cmd.exe /c`, `powershell.exe -enc`, `certutil.exe`, `bitsadmin.exe`
* Recon commands:

  * `whoami`, `systeminfo`, `ipconfig`, `net user`, `net group`, `net localgroup`

### File Inclusion (`FileInclusion`)

Looks for:

* Directory traversal in parameters (`../`, `..%2f`)
* Remote file inclusion:

  * `file=`, `page=`, `include=`, `view=` pointing to `http://`, `https://`, `ftp://`, `php://`, etc.
* Windows paths and UNC paths:

  * `C:\`, `\\server\share`, `%5c%5c`
* `php://` wrappers in parameters (common in PHP RFI attacks)

---

## Output

The resulting CSV contains one row per hit. Columns:

* `File` – Full path to the log file
* `LineNumber` – Line number within that file
* `Type` – `SQLi`, `WebShell`, `FileInclusion`, or `Unknown`
* `Date` – IIS `date` field (if present)
* `Time` – IIS `time` field (if present)
* `ClientIP` – IIS `c-ip` (if present)
* `UriStem` – `cs-uri-stem`
* `UriQuery` – `cs-uri-query`
* `Status` – `sc-status`
* `TimeTaken` – `time-taken`
* `RawLine` – Full original log line

You can load this CSV into Excel, Power BI, your SIEM, or any other tool to:

* Pivot by `ClientIP` to identify attacker IPs
* Pivot by `Type` to separate SQLi/webshell/LFI activity
* Filter by `Status` and `TimeTaken` to look for errors or long-running requests

---

## Example IR Workflow

1. Identify a suspicious SQL Server host with `sqlservr.exe → cmd.exe /c ...`.
2. Use `StartDate` / `EndDate` to narrow IIS logs around that timeframe.
3. Run the scanner with a higher `ThrottleLimit` for speed.
4. Open the CSV and:

   * Filter by `Type = SQLi` or `Type = WebShell`.
   * Group by `ClientIP` and `UriStem` to see which IPs hit which endpoints.
   * Correlate timestamps with host-level EDR/Sysmon logs on the SQL and IIS servers.

---

## Notes & Limitations

* This is heuristic-based detection; **false positives** are expected in noisy environments.
* IIS logs do **not** include POST bodies by default, which limits visibility into some SQLi/WebShell payloads.
* The script assumes **W3C formatted** logs with `#Fields:` header; if fields are missing, those values will be left null.

---

## Roadmap / Ideas

Potential future enhancements:

* Separate `SQL_RCE` category (e.g., `xp_cmdshell` + OS commands)
* Configurable pattern sets via external JSON/YAML
* Output summaries (e.g., top attacking IPs, top hit URIs by type)
* Optional integration with a SIEM / log indexer

---

## License

Add a license of your choice (for example, MIT):

```text
MIT License

Copyright (c) ....

Permission is hereby granted, free of charge, to any person obtaining a copy...
```

*(Or remove this section if you prefer to keep it private.)*
