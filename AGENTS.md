# Project Overview
This project develops a tool that automatically finds Android app intent vulnerabilities and explores vulnerability candidates through static and dynamic analysis. Vulnerability analysis results can be viewed through a web dashboard.

## Directory Structure
project
├── .gitignore
├── AGENTS.md  
├── mcp_server/
├── docker/
│   └── Dockerfile
│
├── data/
│     └── apks/
│           ├── target.txt # list of target apk files to be downloaded automatically
│           └── targets/ # collection of apk files to analyze
│
├── src/ # collection of uitl related to cli tools
│   ├── static/ # static analysis tools
│   ├── dynamic/ # collection of dynamic analysis tools
│   ├── parsing/ # Androguard APK parsing tool
│   └── main.py # integrated orchestration that runs static analysis and dynamic analysis
│   └── UnIntent.py # parses CLI options and runs main.py
│   
├── tools/ # collection of decompilation and analysis tools used by the tool
│       ├── jadx.jar 
│       └── apk # apk file download code
│
├── results/ # directory for static and dynamic analysis results
│       ├── static_result # directory for static analysis result JSON files
│       └── dynamic_result # directory for dynamic analysis result JSON files
│
└── web/ # collection of util related to the web service for checking cli tool results

## Tool Flow
1. APK download
2. Parse APK file with Androguard
3. Derive static analysis candidates for each vulnerability
4. Perform dynamic analysis using adb
5. Provide static and dynamic analysis results to users through the web dashboard

## Dependencies
- python 3.14
- androguard 4.1.4
- flask 3.1.3
- adb 37.0.1

## Code Style and Rules
- Function names are created with a combination of underscores and lowercase letters, like is_admin(), check_authentication()
- All functions express a description of the function's functionality and parameters as a one-line comment
- Follow these naming conventions for Python code:
	- Files: `snake_case.py`
	- Functions and variables: `snake_case`
	- Classes: `PascalCase`
	- Constants: `UPPER_SNAKE_CASE`
