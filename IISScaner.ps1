[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [string]$OutputCsv = "WebAttackHits.csv",

    # File patterns to include (add *.txt if needed)
    [string[]]$IncludeExtensions = @("*.log"),

    # Degree of parallelism
    [int]$ThrottleLimit = 8,

    # Optional file date filters (based on LastWriteTime)
    [datetime]$StartDate,
    [datetime]$EndDate,

    [switch]$VerboseMode
)

if ($VerboseMode) { $VerbosePreference = "Continue" }

Write-Verbose "Root path: $RootPath"
Write-Verbose "Output CSV: $OutputCsv"
Write-Verbose "ThrottleLimit: $ThrottleLimit"

if ($PSBoundParameters.ContainsKey('StartDate')) {
    Write-Verbose ("StartDate filter: {0}" -f $StartDate)
}
if ($PSBoundParameters.ContainsKey('EndDate')) {
    Write-Verbose ("EndDate filter: {0}" -f $EndDate)
}

# --- 1. PATTERNS --------------------------------------------------------------

# SQL Injection (unioned into ONE regex)
$sqlPatterns = @(
    "(\%27|')\s*(or|and)\s*['0-9a-zA-Z]"          # ' or 1=1
    "union\s+select"                              # UNION SELECT
    "select\s+.*\s+from"                          # SELECT ... FROM
    "\binsert\s+into\b"                           # INSERT INTO
    "\bupdate\s+\w+\s+set\b"                      # UPDATE tbl SET
    "\bdelete\s+from\b"                           # DELETE FROM
    "\bdrop\s+(table|database)\b"                 # DROP TABLE/DB
    "\bexec(\s+|\+)?(sp_|xp_)?\w+"                # exec sp_xyz / xp_cmdshell
    "xp_cmdshell"                                 # xp_cmdshell
    "waitfor\s+delay"                             # WAITFOR DELAY
    "sleep\("                                     # sleep(
    "information_schema"                          # information_schema
    "sysobjects"                                  # sysobjects
    "sys\.tables"                                 # sys.tables
    "(\%3B|;)\s*(exec|drop|insert|select|update|delete)"  # stacked queries
)

# Webshell-ish
$webShellPatterns = @(
    "(cmd|shell|webshell|upload|backdoor|wshell|wso|b374k|c99|r57)\.(php|asp|aspx)"
    "(phpinfo|adminer)\.php"
    "(?:cmd|exec|command|shell|upload|file|dir|run)=[^&]{1,200}"
    "(cmd(\.exe)?|powershell(\.exe)?|certutil(\.exe)?|bitsadmin(\.exe)?).*?(/c|\-c|\-enc|\-encodedcommand)"
    "(whoami(?:\.exe)?|systeminfo(?:\.exe)?|ipconfig(?:\.exe)?|net(?:\.exe)?\s+user|net(?:\.exe)?\s+group|net(?:\.exe)?\s+localgroup)"
)

# File inclusion / LFI / RFI
$fileIncPatterns = @(
    "(?:file|page|path|template|include|inc|view|style|name|document|doc)=.*?(\.\./|\.\.%2f)+"
    "(?:file|page|path|template|include|inc|view|url|source)=\s*(https?|ftp|sftp|gopher|php):"
    "(?:file|page|path|template|include|inc|view|name)=.*?(?:[A-Za-z]:\\|\\\\|%5c%5c)"
    "(?:file|page|path|template|include|inc|view|source)=.*?php://[a-z]+"
)

# Build unioned regex strings (no (?i), we’ll use IgnoreCase)
$SqlPattern       = '(' + ($sqlPatterns      -join '|') + ')'
$WebShellPattern  = '(' + ($webShellPatterns -join '|') + ')'
$FileIncPattern   = '(' + ($fileIncPatterns  -join '|') + ')'

# One combined regex string – used as a single gate
$CombinedPattern = $SqlPattern + '|' + $WebShellPattern + '|' + $FileIncPattern

Write-Verbose "Combined regex: $CombinedPattern"

# --- 2. Get IIS log files -----------------------------------------------------

$files = Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction SilentlyContinue |
         Where-Object {
             foreach ($ext in $IncludeExtensions) {
                 if ($_.Name -like $ext) { return $true }
             }
             return $false
         }

if (-not $files) {
    Write-Warning "No log files found under $RootPath matching: $($IncludeExtensions -join ', ')"
    return
}

# Apply date filters on LastWriteTime if provided
if ($PSBoundParameters.ContainsKey('StartDate')) {
    $files = $files | Where-Object { $_.LastWriteTime -ge $StartDate }
}
if ($PSBoundParameters.ContainsKey('EndDate')) {
    $files = $files | Where-Object { $_.LastWriteTime -le $EndDate }
}

if (-not $files -or $files.Count -eq 0) {
    Write-Warning "After applying date filters, no files remain to scan."
    return
}

Write-Verbose ("Files to scan after filters: {0}" -f $files.Count)

# --- 3. Parallel scan per file (streaming with ReadLines) ---------------------

$results =
    $files |
    ForEach-Object -Parallel {
        param()

        # Bring stuff into the runspace
        $file            = $_
        $combinedPattern = $using:CombinedPattern
        $sqlPattern      = $using:SqlPattern
        $webShellPattern = $using:WebShellPattern
        $fileIncPattern  = $using:FileIncPattern
        $outerVerbose    = $using:VerboseMode

        if ($outerVerbose) { $VerbosePreference = "Continue" }

        Write-Verbose "Scanning $($file.FullName)"

        # Compile regexes locally
        $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                   [System.Text.RegularExpressions.RegexOptions]::Compiled

        $combinedRegex = [regex]::new($combinedPattern, $options)
        $sqlRegex      = [regex]::new($sqlPattern,      $options)
        $webRegex      = [regex]::new($webShellPattern, $options)
        $fileRegex     = [regex]::new($fileIncPattern,  $options)

        $fieldMap     = $null
        $localResults = New-Object System.Collections.Generic.List[object]
        $lineNumber   = 0

        try {
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                $lineNumber++

                if ([string]::IsNullOrWhiteSpace($line)) { continue }

                # Header / comments handling
                if ($line.StartsWith("#Fields:")) {
                    $fields = $line.Substring(8).Trim() -split "\s+"
                    $fieldMap = @{}
                    for ($i = 0; $i -lt $fields.Count; $i++) {
                        $fieldMap[$fields[$i]] = $i
                    }
                    continue
                }

                if ($line.StartsWith("#")) {
                    # Other comment lines – skip
                    continue
                }

                # Fast gate: if no interesting pattern, skip
                if (-not $combinedRegex.IsMatch($line)) {
                    continue
                }

                # Classify type
                $type = if ($sqlRegex.IsMatch($line)) {
                    'SQLi'
                } elseif ($webRegex.IsMatch($line)) {
                    'WebShell'
                } elseif ($fileRegex.IsMatch($line)) {
                    'FileInclusion'
                } else {
                    'Unknown'
                }

                $tokens = $line -split "\s+"

                $date      = $null
                $time      = $null
                $cIp       = $null
                $uriStem   = $null
                $uriQuery  = $null
                $status    = $null
                $timeTaken = $null

                if ($fieldMap) {
                    if ($fieldMap.ContainsKey("date") -and $tokens.Count -gt $fieldMap["date"]) {
                        $date = $tokens[$fieldMap["date"]]
                    }
                    if ($fieldMap.ContainsKey("time") -and $tokens.Count -gt $fieldMap["time"]) {
                        $time = $tokens[$fieldMap["time"]]
                    }
                    if ($fieldMap.ContainsKey("c-ip") -and $tokens.Count -gt $fieldMap["c-ip"]) {
                        $cIp = $tokens[$fieldMap["c-ip"]]
                    }
                    if ($fieldMap.ContainsKey("cs-uri-stem") -and $tokens.Count -gt $fieldMap["cs-uri-stem"]) {
                        $uriStem = $tokens[$fieldMap["cs-uri-stem"]]
                    }
                    if ($fieldMap.ContainsKey("cs-uri-query") -and $tokens.Count -gt $fieldMap["cs-uri-query"]) {
                        $uriQuery = $tokens[$fieldMap["cs-uri-query"]]
                    }
                    if ($fieldMap.ContainsKey("sc-status") -and $tokens.Count -gt $fieldMap["sc-status"]) {
                        $status = $tokens[$fieldMap["sc-status"]]
                    }
                    if ($fieldMap.ContainsKey("time-taken") -and $tokens.Count -gt $fieldMap["time-taken"]) {
                        $timeTaken = $tokens[$fieldMap["time-taken"]]
                    }
                }

                $localResults.Add([pscustomobject]@{
                    File       = $file.FullName
                    LineNumber = $lineNumber
                    Type       = $type
                    Date       = $date
                    Time       = $time
                    ClientIP   = $cIp
                    UriStem    = $uriStem
                    UriQuery   = $uriQuery
                    Status     = $status
                    TimeTaken  = $timeTaken
                    RawLine    = $line
                })
            }
        }
        catch {
            Write-Verbose "Error reading $($file.FullName): $($_.Exception.Message)"
        }

        $localResults
    } -ThrottleLimit $ThrottleLimit

# --- 4. Aggregate results -----------------------------------------------------

if ($results -and $results.Count -gt 0) {
    Write-Verbose ("Found {0} potential web attack hit(s)." -f $results.Count)
    $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $($results.Count) hits to $OutputCsv"
} else {
    Write-Host "No potential SQLi / webshell / file inclusion patterns found under $RootPath"
}
