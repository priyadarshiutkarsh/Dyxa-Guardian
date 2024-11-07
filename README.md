# 🛡️ Dyxa Guardian

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Cerebras](https://img.shields.io/badge/powered%20by-Cerebras-orange.svg)](https://www.cerebras.net/)

*A real-time Python code security analyzer powered by Cerebras API*

[Key Features](#key-features) • [Installation](#installation) • [Usage](#usage) • [Demo](#demo) • [Requirements](#-requirements) • [Security Features](#-security-features) • [Contributing](#-contributing)

![Dyxa Guardian Demo](https://your-demo-gif-url-here.gif)

</div>

## 🌟 Key Features

- 🔍 Real-time code security analysis
- 🚨 Detection of common vulnerabilities:
  - SQL Injection
  - XSS Vulnerabilities
  - Command Injection
  - Hardcoded Secrets
  - Unsafe Deserialization
  - Path Traversal
- 💡 Intelligent suggestions for secure alternatives
- 🎨 Beautiful, intuitive web interface
- 🤖 Powered by Cerebras AI

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dyxa-guardian.git
cd dyxa-guardian

# Install required packages
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Add your Cerebras API key to .env file

## 💻 USAGE

# Run the application
python dyxa_guardian.py

## 🔧 Configuration

CEREBRAS_API_KEY=your_api_key_here



