# Claude tools for analyzing nmap output
This directory contains a script, `redact.py`, and a Claude skill, `nmap-report`. Sanitize your nmap output before using Claude to analyze the output.
```shell
python3 redact.py client-nmap-output.nmap sanitized.nmap`
```
**Note:** The sanitizer tries to account for most client data found in nmap output but it may miss things. Spot check the file with grep or visual inspection first.

After sanitizing your nmap script, use the Claude skill by saying "Analyze this nmap output for vulnerabilities" or "Analyze this nmap output and generate an HTML vulnerability report."

## Installation
Copy the `nmap-report` directory to `~/.claude/skills/`
