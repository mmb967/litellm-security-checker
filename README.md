# LiteLLM Supply Chain Attack Checker

A local security diagnostic tool to check if your machine was affected by the [litellm PyPI supply chain attack](https://blog.pypi.org/posts/2025-03-litellm-attack/).

## What happened

A malicious version of `litellm` was published to PyPI that exfiltrated SSH keys, cloud credentials (AWS/GCP/Azure), Kubernetes configs, git credentials, environment variables, shell history, crypto wallets, SSL private keys, CI/CD secrets, and database passwords.

The poisoned version was live for approximately 1 hour. The attack spread transitively through packages that depend on litellm, including `dspy`, `crewai`, `langgraph`, and Cursor MCP plugins.

## What this tool does

One-click scan that checks your local machine:

1. **Detects litellm** across system Python and virtual environments
2. **Analyzes the version** against the known danger zone (~1.64.x)
3. **Finds dependent packages** that could have pulled litellm transitively (dspy, crewai, langgraph, etc.)
4. **Audits sensitive file timestamps** (~/.ssh, ~/.aws, ~/.kube, git credentials, shell history, etc.)
5. **Lists exposed environment variables** (values are redacted)
6. **Generates a copy-paste report** with prioritized remediation steps

## Privacy

- Runs entirely on your local machine. No data is sent anywhere.
- Environment variable values are redacted in all output.
- The generated report contains only variable names, file paths, and timestamps -- no secrets.

## Requirements

- Python 3.9+
- macOS or Linux

## Usage

```bash
pip install streamlit
streamlit run app.py
```

Click "Run Full Security Scan" and review the results.

## Screenshot

After scanning, you'll see a step-by-step report with a verdict and a downloadable action plan.

## License

MIT
