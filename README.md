# LLM Security Tester

## Overview

The LLM Security Tester is a Python script designed to evaluate the security and robustness of Large Language Models (LLMs) running on the Ollama platform. This tool performs a series of security tests to identify potential vulnerabilities in AI model responses.

![alt text](https://github.com/xdep/llm-security-checks/example1.PNG)
![alt text](https://github.com/xdep/llm-security-checks/example2.PNG)

## Features

- **Security Testing**: Covers multiple security test categories
- **Detailed Reporting**: Generates detailed logs and summarized test results
- **Adjustable Configuration**: Supports testing multiple models and test categories
- **Visualization**: Uses Rich library for enhanced console output

## Test Categories

The tool includes tests across seven critical security domains:

1. **Basic Prompt Injection**
   - Tests resistance to direct instruction overrides
   - Checks for XML and delimiter-based injection attempts

2. **Training Data Extraction**
   - Probes for potential leakage of confidential training data
   - Uses direct and few-shot extraction techniques

3. **Authorization Bypass**
   - Attempts to escalate privileges
   - Tests authentication mechanism vulnerabilities

4. **Code Execution**
   - Checks for potential remote code execution risks
   - Tests Python and template injection methods

5. **Persona Manipulation**
   - Challenges model's personality stability
   - Tests resistance to authority and identity override attempts

6. **Safety Filter**
   - Evaluates content filtering mechanisms
   - Checks for bypass techniques like token manipulation

7. **Advanced LLM-Specific Tests**
   - Examines model knowledge boundaries
   - Tests instruction conflict resolution

## Installation

### Prerequisites

- Python 3.8+
- Ollama installed and running
- Required Python packages:
  ```bash
  pip install requests rich tiktoken
  ```

### Setup

1. Clone the repository:
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
python llm_security.py
```

### Command-Line Options

- `--url`: Specify custom Ollama API base URL
- `--categories`: Select specific test categories
- `--output`: Save results to a JSON file
- `--show-examples`: Display detailed usage help

### Examples

1. Run all test categories:
   ```bash
   python ollama_tester.py --categories all
   ```

2. Test specific categories:
   ```bash
   python ollama_tester.py --categories prompt,safety
   ```

3. Use custom Ollama URL:
   ```bash
   python ollama_tester.py --url http://localhost:7869
   ```

4. Save results to file:
   ```bash
   python ollama_tester.py --output results.json
   ```

## Output

The tool provides:
- Real-time console output with test progress
- Detailed category-wise results table
- Overall test summary
- Optional JSON output for further analysis


## License

Distributed under the MIT License. See `LICENSE` for more information.

**Disclaimer**: This tool is for educational and research purposes. Always use responsibly and ethically.
