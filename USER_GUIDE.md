# Superscan User Guide

## What is Superscan?
Superscan is a security tool that helps you find "secrets" hidden in your code. Secrets are things like:
- Passwords
- API Keys (AWS, Google, Stripe, etc.)
- Database credentials
- Private encryption keys

If these get uploaded to GitHub or shared publicly, hackers can use them to steal data or money. Superscan acts like a "spellchecker" for security, finding these mistakes before they become problems.

## How It Works
1. **Reads Files**: It looks through every file in your folder (skipping things like `.git` or `node_modules`).
2. **Pattern Matching**: It uses a list of known "shapes" of secrets (defined in `config.yml`). For example, it knows that an AWS key usually starts with "AKIA".
3. **Entropy Check**: It looks for random-looking strings (like `7Fz9a2B1x8...`). Passwords usually look like random gibberish, while normal code looks like English words.
4. **Reporting**: It prints a list of everything it found so you can fix it.

## Installation

Before you can use Superscan, you need to build it from source:

1. **Install Go**: Download and install Go (version 1.22 or later) from [go.dev](https://go.dev/dl/).
2. **Build the Tool**:
   Open PowerShell in the project folder and run:
   ```powershell
   go mod tidy
   go build -o superscan.exe ./cmd/superscan
   ```
   This will create the `superscan.exe` file.

## Verifying Your Installation

To make sure Superscan is working correctly on your machine, run the included verification script:

```powershell
.\verify_full.ps1
```

This script will:
1. Build the project.
2. Create a temporary test file with fake secrets.
3. Run Superscan in various modes (Text, JSON, SARIF).
4. Verify that secrets are detected correctly.
5. Clean up temporary files.

If you see "All System Checks Passed!", you are ready to scan!

## How to Use It

**Important**: This is a command-line tool. You cannot run it by double-clicking the `.exe` file. You must use a terminal (like PowerShell or Command Prompt).

### Step 1: Open PowerShell
1. Press the `Windows Key`.
2. Type `PowerShell`.
3. Press `Enter`.

### Step 2: Go to the Folder
Type `cd` followed by the path to the folder where `superscan.exe` is located.
Example:
```powershell
cd C:\Users\lsanj\Desktop\superscan_full_project\superscan_full
```

### Step 3: Run a Scan
To scan all files in the current folder, type:
```powershell
.\superscan.exe .
```
*(Don't forget the dot `.` at the end! It means "this folder".)*

### Scanning Other Folders
You can scan any folder on your computer, not just the one you are in. Just replace the dot `.` with the path to the other folder.

Example:
```powershell
.\superscan.exe C:\Users\lsanj\Documents\MyOtherProject
```

### Scanning GitHub Repositories
Superscan scans files on your **computer**, not on the internet. To scan a GitHub repository:
1. **Download it** (Clone it):
   ```powershell
   git clone https://github.com/username/repo-name.git
   ```
2. **Scan the downloaded folder**:
   ```powershell
   .\superscan.exe .\repo-name
   ```

### Step 4: Read the Results
- **Red/Critical**: These are likely real secrets. Fix them immediately!
- **Medium/Low**: These might be secrets, or they might be false alarms. Check them to be sure.

### Advanced Features

**Save Output to a File**:
By default, results are just shown on the screen. To save them to a file, use the `>` symbol.

Save as text:
```powershell
.\superscan.exe . > results.txt
```

Save as JSON (for other tools):
```powershell
.\superscan.exe --json . > results.json
```

**Save as SARIF (GitHub Security Standard)**:
This is a "Pro" feature. SARIF is the standard format used by GitHub Advanced Security.
```powershell
.\superscan.exe --sarif . > results.sarif
```
You can upload this file to GitHub to see alerts in the "Security" tab of your repo.

**Ignore Old Issues (Baselines)**:
If you have old secrets you can't fix right now, you can "ignore" them so you only see *new* problems.
1. Create the baseline file:
   ```powershell
   .\superscan.exe --baseline-create --baseline my_baseline.json .
   ```
2. Run future scans using that baseline:
   ```powershell
   .\superscan.exe --baseline my_baseline.json .
   ```

### Customizing Rules
You can teach Superscan to find new things by editing `config.yml`.
- **Default Config**: Superscan automatically looks for `config.yml` in the current directory.
- **Custom Config**: You can specify a different file using the `--config` flag:
  ```powershell
  .\superscan.exe --config my_custom_config.yml .
  ```
- **Add new patterns**: If your company uses a specific token format (e.g., `MYAPP-1234`), you can add a regex rule for it.
- **Ignore Folders**: Add folders to `ignore_dirs` to speed up scanning (e.g., `test_data`, `logs`).

### CI/CD Integration (Automation)
Superscan is designed to run automatically in pipelines (like GitHub Actions or Jenkins).
- **Exit Codes**: It tells the computer if it failed.
  - Exit Code `0`: Clean (or low severity only).
  - Exit Code `1`: High severity found.
  - Exit Code `2`: Critical severity found.
## Author

**Superscan** is developed by **Lahiru Sanjika Kulasuriya**.
Source code is available on [GitHub](https://github.com/lahirusanjika/Super-scan).

