# Dyxa Guardian

Dyxa Guardian is a powerful code security analyzer designed to help developers identify vulnerabilities in their code. It supports multiple programming languages and provides detailed reports on security issues, making it an essential tool for secure software development.

## ✨ Features

- **Multi-Language Support**: Analyze code in Python, JavaScript, Java, and C++.
- **Security Issue Detection**: Identify vulnerabilities such as SQL Injection, XSS, insecure deserialization, and more.
- **Interactive Web Interface**: Built with Gradio for an easy-to-use and intuitive experience.
- **Export Reports**: Export analysis results in JSON, CSV, or PDF formats.
- **User Authentication**: Flask-based user registration and login system.
- **Code Metrics**: Analyze code complexity and lines of code (LOC).

## 🛠️ Installation

### Clone the Repository:

```bash
git clone https://github.com/yourusername/dyxa-guardian.git
cd dyxa-guardian
```

### Install Dependencies:

```bash
pip install -r requirements.txt
```

### Set Up Environment Variables:

Create a `.env` file in the project root and add your `CEREBRAS_API_KEY`:

```env
CEREBRAS_API_KEY=your_api_key_here
```

## 🚀 Usage

### Running the Gradio Interface

Start the Gradio app:

```bash
python gradio_interface.py
```

Open the provided URL in your browser.

- Paste your code into the input box, select the language, and click **Analyze Code**.
- View the results, including vulnerability distribution, code metrics, and issue details.
- Export the report in JSON, CSV, or PDF format.

### Running the Flask App

Start the Flask app for user authentication:

```bash
python flask_app.py
```

- Use the `/register` endpoint to create a new user and the `/login` endpoint to authenticate.

## 🗂️ Project Structure

```plaintext
dyxa-guardian/
│
├── security_analyzer.py       # Core logic for code security analysis
├── gradio_interface.py        # Gradio web interface for code analysis
├── flask_app.py               # Flask app for user authentication
├── config.py                  # Configuration settings
├── requirements.txt           # List of required Python packages
├── README.md                  # Project documentation
├── .env.example               # Template for environment variables
└── .gitignore                 # Files and directories to ignore in version control
```

## 🛡️ Supported Vulnerabilities

Dyxa Guardian can detect a wide range of security issues, including:

- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Insecure Deserialization**
- **Hardcoded Credentials**
- **Insecure File Handling**
- **Weak Cryptographic Algorithms**
- **Missing CSRF Tokens**
- **Server-Side Request Forgery (SSRF)**
- **XML External Entity (XXE) Injection**

## 📊 Screenshot of Gradio Interface

![Gradio Interface Screenshot](attachment://Screenshot%202024-12-30%20at%209.38.09%E2%80%AFpm.png)

## 🤝 Contributing

Contributions are welcome! If you'd like to contribute to Dyxa Guardian, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes and push to your branch.
4. Submit a pull request with a detailed description of your changes.

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## 🙏 Acknowledgments

- **Gradio** for the interactive web interface.
- **Flask** for user authentication.
- **Radon** for code complexity analysis.
- **Plotly** for data visualization.

## 📧 Contact

For questions or feedback, feel free to reach out:

- **Email**: priyadarshiutkarshofficial@gmail.com
- **GitHub**: [priyadarshiutkarsh](https://github.com/priyadarshiutkarsh)
