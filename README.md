🛡️ Dyxa Guardian
<div align="center">
Python VersionLicenseCerebras

A real-time Python code security analyzer powered by Cerebras API

Key Features • Installation • Usage • Demo • Contributing

Dyxa Guardian Demo

</div>
🌟 Key Features
🔍 Real-time code security analysis
🚨 Detection of common vulnerabilities:
SQL Injection
XSS Vulnerabilities
Command Injection
Hardcoded Secrets
Unsafe Deserialization
Path Traversal
💡 Intelligent suggestions for secure alternatives
🎨 Beautiful, intuitive web interface
🤖 Powered by Cerebras AI
🚀 Installation
bash

Verify

Open In Editor
Edit
Copy code
# Clone the repository
git clone https://github.com/yourusername/dyxa-guardian.git
cd dyxa-guardian

# Install required packages
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Add your Cerebras API key to .env file
📋 Requirements
plaintext

Verify

Open In Editor
Edit
Copy code
cerebras_cloud_sdk
networkx
matplotlib
gradio
requests
python-dotenv
💻 Usage
python

Verify

Open In Editor
Edit
Copy code
# Run the application
python dyxa_guardian.py
The web interface will be available at http://localhost:7860

🔧 Configuration
Create a .env file in the project root:

env

Verify

Open In Editor
Edit
Copy code
CEREBRAS_API_KEY=your_api_key_here
🎮 Demo
Access the web interface
Paste your Python code in the input box
Get instant security analysis with:
Severity levels
Line-specific issues
Code snippets
Recommended fixes
🔒 Security Features
Feature	Description
Static Analysis	AST-based code scanning
Dynamic Analysis	AI-powered vulnerability detection
Real-time Monitoring	Instant feedback on code changes
Secure Suggestions	AI-generated security improvements
🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request
📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
Powered by Cerebras API
Built with Gradio

Project Link: https://github.com/priyadarshiutkarsh/dyxa-guardian

<div align="center"> Made with ❤️ Utkarsh Priyadarshi </div>
