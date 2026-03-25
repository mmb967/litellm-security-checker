import streamlit as st
import subprocess
import os
import re
import platform

st.set_page_config(
    page_title="LiteLLM Supply Chain Attack Checker",
    page_icon="🔒",
    layout="centered",
)

st.markdown("""
<style>
.danger-box {
    background-color: #2d1117;
    border: 2px solid #f85149;
    border-radius: 8px;
    padding: 16px;
    margin: 8px 0;
}
.safe-box {
    background-color: #0d1117;
    border: 2px solid #3fb950;
    border-radius: 8px;
    padding: 16px;
    margin: 8px 0;
}
.warn-box {
    background-color: #2d1f00;
    border: 2px solid #d29922;
    border-radius: 8px;
    padding: 16px;
    margin: 8px 0;
}
</style>
""", unsafe_allow_html=True)

HOME = os.path.expanduser("~")
IS_MACOS = platform.system() == "Darwin"


def run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def get_file_mod_time(filepath):
    """Get file modification time, cross-platform."""
    if IS_MACOS:
        return run_cmd(f'stat -f "%Sm" "{filepath}" 2>/dev/null', timeout=5)
    else:
        return run_cmd(f'stat -c "%y" "{filepath}" 2>/dev/null | cut -d. -f1', timeout=5)


def classify_version(ver_str):
    """Returns 'danger', 'warning', 'safe', or None if unparseable."""
    try:
        parts = [int(x) for x in ver_str.strip().lstrip("v").split(".")]
        major, minor = parts[0], parts[1] if len(parts) > 1 else 0
        if major == 1 and minor == 64:
            return "danger"
        if major == 1 and 63 <= minor <= 65:
            return "warning"
        return "safe"
    except (ValueError, IndexError):
        return None


# ── Header ──────────────────────────────────────────────────────────────
st.title("LiteLLM Supply Chain Attack Checker")

st.markdown("""
**What happened:** A malicious `litellm` version on PyPI exfiltrated SSH keys,
cloud credentials (AWS/GCP/Azure), Kubernetes configs, git credentials,
env vars, shell history, crypto wallets, SSL keys, CI/CD secrets, and DB passwords.

The poisoned version was live for ~1 hour. Packages depending on `litellm`
(dspy, crewai, langgraph, Cursor MCP plugins) could have pulled it transitively.
""")

st.divider()

# ── Single button to run full scan ──────────────────────────────────────
if st.button("Run Full Security Scan", type="primary", use_container_width=True):
    affected = False
    report_lines = []  # accumulate findings for the copyable report

    # ── STEP 1: Detect litellm ──────────────────────────────────────────
    st.header("1. Checking for litellm installations")
    with st.spinner("Scanning Python environments..."):
        litellm_found = []
        seen_versions = set()
        pip_cmds = [
            ("pip", "pip list 2>/dev/null | grep -i litellm"),
            ("pip3", "pip3 list 2>/dev/null | grep -i litellm"),
            ("python3 -m pip", "python3 -m pip list 2>/dev/null | grep -i litellm"),
        ]
        for label, cmd in pip_cmds:
            out = run_cmd(cmd)
            if out and out not in seen_versions:
                seen_versions.add(out)
                litellm_found.append((label, out))

        # Check venvs under home and common project dirs
        venv_out = run_cmd(
            f'find "{HOME}" -path "*/site-packages/litellm/__init__.py" -maxdepth 8 2>/dev/null | head -10',
            timeout=20,
        )
        if venv_out:
            for line in venv_out.strip().split("\n"):
                path = line.strip()
                # Extract version from the package
                ver = run_cmd(f'python3 -c "import ast; f=open(\'{path}\'); [print(l.split(\\\"=\\\")[1].strip().strip(chr(34))) for l in f if l.startswith(\\\"version\\\")]" 2>/dev/null')
                if not ver:
                    ver = run_cmd(f'grep -m1 "^Version:" "{os.path.dirname(path)}/../litellm.dist-info/METADATA" 2>/dev/null | cut -d" " -f2')
                short_path = path.replace(HOME, "~")
                litellm_found.append(("venv: " + short_path, f"litellm {ver}" if ver else "litellm (version unknown)"))

    if litellm_found:
        st.warning(f"litellm found in {len(litellm_found)} environment(s):")
        for label, detail in litellm_found:
            st.markdown(f"- **{label}:** `{detail}`")
        affected = True
        report_lines.append("## Scan Results: litellm Installation")
        report_lines.append(f"FOUND in {len(litellm_found)} environment(s):")
        for label, detail in litellm_found:
            report_lines.append(f"  - {label}: {detail}")
    else:
        st.success("litellm is NOT installed in any detected Python environment.")
        report_lines.append("## Scan Results: litellm Installation")
        report_lines.append("NOT FOUND in any detected Python environment.")

    # ── STEP 2: Version analysis (auto, no user input needed) ───────────
    if litellm_found:
        st.header("2. Version Analysis")
        report_lines.append("")
        report_lines.append("## Version Analysis")
        for label, detail in litellm_found:
            # Extract version number from strings like "litellm 1.64.0"
            match = re.search(r"(\d+\.\d+(?:\.\d+)?)", detail)
            if match:
                ver = match.group(1)
                verdict = classify_version(ver)
                if verdict == "danger":
                    st.markdown(f"""<div class="danger-box">
                    <h3>CRITICAL: {label} has version {ver} — IN THE DANGER ZONE</h3>
                    <p>This version was targeted by the supply chain attack. Assume compromise.</p>
                    </div>""", unsafe_allow_html=True)
                    affected = True
                    report_lines.append(f"  - CRITICAL: {label} version {ver} — IN DANGER ZONE. Assume compromise.")
                elif verdict == "warning":
                    st.markdown(f"""<div class="warn-box">
                    <h3>WARNING: {label} has version {ver} — near affected range</h3>
                    <p>Verify package integrity. Consider treating as compromised.</p>
                    </div>""", unsafe_allow_html=True)
                    affected = True
                    report_lines.append(f"  - WARNING: {label} version {ver} — near affected range. Verify integrity.")
                else:
                    st.markdown(f"""<div class="safe-box">
                    <h3>{label}: version {ver} — outside known danger zone</h3>
                    <p>Update to latest as a precaution.</p>
                    </div>""", unsafe_allow_html=True)
                    report_lines.append(f"  - OK: {label} version {ver} — outside danger zone. Update as precaution.")
            else:
                st.warning(f"Could not determine version for **{label}**: `{detail}`")
                report_lines.append(f"  - {label}: version unknown")
        report_lines.append("")
    else:
        st.header("2. Version Analysis")
        st.info("Skipped — litellm not found.")
        report_lines.append("")
        report_lines.append("## Version Analysis")
        report_lines.append("Skipped — litellm not found.")
        report_lines.append("")

    # ── STEP 3: Check dependent packages ────────────────────────────────
    st.header("3. Checking packages that depend on litellm")
    dep_packages = {
        "dspy": "dspy (required litellm>=1.64.0)",
        "crewai": "crewai",
        "langgraph": "langgraph",
        "langchain": "langchain (some configs)",
        "autogen": "autogen / pyautogen",
        "promptflow": "promptflow",
        "guardrails-ai": "guardrails-ai",
    }

    with st.spinner("Checking dependent packages..."):
        pip_list = run_cmd("pip list 2>/dev/null")
        found_deps = []
        for pkg, desc in dep_packages.items():
            if re.search(rf"(?i)^{re.escape(pkg)}\s", pip_list, re.MULTILINE):
                line = [l for l in pip_list.split("\n") if re.search(rf"(?i)^{re.escape(pkg)}\s", l)]
                found_deps.append((desc, line[0] if line else pkg))

    report_lines.append("")
    report_lines.append("## Dependent Packages")
    if found_deps:
        st.warning(f"Found {len(found_deps)} package(s) that may depend on litellm:")
        for desc, detail in found_deps:
            st.markdown(f"- **{desc}**: `{detail}`")
        st.markdown("These could have pulled litellm as a transitive dependency even if litellm isn't directly installed.")
        for desc, detail in found_deps:
            report_lines.append(f"  - FOUND: {detail}")
        report_lines.append("  These may have pulled litellm as a transitive dependency.")
    else:
        st.success("No common litellm-dependent packages found.")
        report_lines.append("  None of the common litellm-dependent packages found.")

    st.caption("Also check: Cursor IDE MCP plugins that use litellm internally.")

    # ── STEP 4: Sensitive file modification times ───────────────────────
    st.header("4. Sensitive File Modification Audit")
    sensitive_paths = [
        ("~/.ssh", "SSH keys"),
        ("~/.aws/credentials", "AWS credentials"),
        ("~/.aws/config", "AWS config"),
        ("~/.azure", "Azure credentials"),
        ("~/.config/gcloud", "GCP credentials"),
        ("~/.kube/config", "Kubernetes config"),
        ("~/.gitconfig", "Git config"),
        ("~/.git-credentials", "Git stored credentials"),
        ("~/.bash_history", "Bash history"),
        ("~/.zsh_history", "Zsh history"),
        ("~/.gnupg", "GPG keys"),
        ("~/.docker/config.json", "Docker config"),
        ("~/.npmrc", "NPM config (may contain tokens)"),
        ("~/.pypirc", "PyPI config (may contain tokens)"),
        ("~/.env", "Environment file"),
    ]

    with st.spinner("Checking sensitive file timestamps..."):
        file_results = []
        for path, desc in sensitive_paths:
            expanded = path.replace("~", HOME)
            mod_time = get_file_mod_time(expanded)
            if mod_time:
                file_results.append((desc, path, mod_time, True))
            else:
                file_results.append((desc, path, "", False))

    present = [(d, p, t) for d, p, t, exists in file_results if exists]
    absent = [(d, p) for d, p, t, exists in file_results if not exists]

    report_lines.append("")
    report_lines.append("## Sensitive File Modification Timestamps")
    if present:
        st.markdown("**Files found — review timestamps for unexpected recent modifications:**")
        for desc, path, mod_time in present:
            st.markdown(f"- `{path}` ({desc}): **{mod_time}**")
            report_lines.append(f"  - {path} ({desc}): {mod_time}")
    if absent:
        with st.expander(f"{len(absent)} sensitive paths not present (click to expand)"):
            for desc, path in absent:
                st.markdown(f"- `{path}` ({desc}): *not found*")
        report_lines.append(f"  {len(absent)} sensitive paths not present on this system.")

    # ── STEP 5: Exposed environment variables ───────────────────────────
    st.header("5. Potentially Exposed Environment Variables")
    with st.spinner("Checking env vars..."):
        env_out = run_cmd("env | grep -iE 'key|token|secret|password|api|auth' | sort")

    report_lines.append("")
    report_lines.append("## Potentially Exposed Environment Variables")
    if env_out:
        redacted_lines = []
        for line in env_out.split("\n"):
            if "=" in line:
                key = line.split("=", 1)[0]
                redacted_lines.append(f"{key}=***")
            else:
                redacted_lines.append(line)
        st.warning(f"Found {len(redacted_lines)} env vars matching sensitive patterns (values redacted):")
        st.code("\n".join(redacted_lines), language="text")
        st.markdown("If compromised, **all of these** should be rotated.")
        report_lines.append(f"  Found {len(redacted_lines)} env vars with sensitive patterns (values redacted):")
        for rl in redacted_lines:
            report_lines.append(f"    - {rl}")
    else:
        st.success("No sensitive-looking environment variables detected.")
        report_lines.append("  No sensitive-looking environment variables detected.")

    # ── STEP 6: Verdict + Remediation ───────────────────────────────────
    st.divider()
    st.header("6. Verdict & Remediation")

    if affected:
        st.markdown("""<div class="danger-box">
        <h3>Action Required</h3>
        <p>litellm or a dependent package was detected. Follow the remediation steps below.</p>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown("""<div class="safe-box">
        <h3>No direct exposure detected</h3>
        <p>litellm was not found on this system. You appear unaffected, but review the
        steps below if you used litellm recently and have since uninstalled it.</p>
        </div>""", unsafe_allow_html=True)

    st.markdown("### Remediation Steps")

    with st.expander("1. Update or remove litellm", expanded=affected):
        st.code("pip install --upgrade litellm\n# or remove entirely:\npip uninstall litellm -y", language="bash")
        st.code("pip install --upgrade dspy crewai langgraph 2>/dev/null", language="bash")

    with st.expander("2. Rotate SSH keys", expanded=affected):
        st.code("""# Back up old keys
cp -r ~/.ssh ~/.ssh.backup.$(date +%s)

# Generate new key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Update on GitHub
gh ssh-key add ~/.ssh/id_ed25519.pub --title "rotated $(date +%Y-%m-%d)\"""", language="bash")
        st.markdown("Remove old keys from: GitHub, GitLab, Bitbucket, all servers.")

    with st.expander("3. Rotate cloud credentials", expanded=affected):
        st.markdown("**AWS:**")
        st.code("""aws iam create-access-key
# Update ~/.aws/credentials with the new key
# Then delete the old one:
# aws iam delete-access-key --access-key-id OLD_KEY_ID""", language="bash")
        st.markdown("**GCP:**")
        st.code("gcloud auth revoke --all && gcloud auth login", language="bash")
        st.markdown("**Azure:**")
        st.code("az logout && az login", language="bash")

    with st.expander("4. Rotate ALL API keys and tokens", expanded=affected):
        st.markdown("""
Rotate every key that was in your env or `.env` files:
- OpenAI, Anthropic, and other LLM provider keys
- Database passwords and connection strings
- NPM / PyPI tokens
- Slack / Discord webhooks
- Any service account credentials
""")

    with st.expander("5. Check cloud audit logs", expanded=False):
        st.markdown("**AWS CloudTrail:**")
        st.code('aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --start-time "2025-03-20T00:00:00Z" --end-time "2025-03-25T00:00:00Z"', language="bash")
        st.markdown("**GCP:**")
        st.code("gcloud logging read 'logName=\"projects/YOUR_PROJECT/logs/cloudaudit.googleapis.com%2Factivity\"' --limit=50 --freshness=7d", language="bash")

    with st.expander("6. Review git config", expanded=False):
        st.code("git config --global --list\ngit config --global credential.helper", language="bash")

    with st.expander("7. Check pip install logs", expanded=False):
        st.code("pip cache list litellm 2>/dev/null\nls -la ~/.pip/pip.log 2>/dev/null", language="bash")

    with st.expander("8. Run antivirus scan", expanded=False):
        st.code("# macOS with ClamAV:\nbrew install clamav && freshclam && clamscan -r --bell -i ~", language="bash")

    # ── STEP 7: Copyable Report ─────────────────────────────────────────
    st.divider()
    st.header("7. Copy-Paste Report")
    st.markdown("Full scan results and action plan. Copy this into Claude Code, a ticket, Slack, etc.")

    # Build the comprehensive report
    from datetime import datetime
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_level = "HIGH — litellm or dependent package detected" if affected else "LOW — no litellm exposure detected"

    report = f"""# LiteLLM Supply Chain Attack — Security Scan Report
Scan time: {scan_time}
Machine: {run_cmd("hostname")} ({run_cmd("uname -m")})
Risk level: {risk_level}

---

# Background

A malicious version of litellm was published to PyPI that exfiltrated:
- SSH keys (~/.ssh)
- AWS/GCP/Azure credentials
- Kubernetes configs (~/.kube/config)
- Git credentials and config
- All environment variables (API keys, tokens, passwords)
- Shell history (~/.bash_history, ~/.zsh_history)
- Crypto wallets
- SSL/TLS private keys
- CI/CD secrets
- Database passwords
- Docker, NPM, PyPI configs

The poisoned version was live for approximately 1 hour. The attack spread
transitively through packages that depend on litellm, including dspy
(required litellm>=1.64.0), crewai, langgraph, and Cursor MCP plugins.

The attack was discovered by Callum McMahon due to a bug in the malware.

---

{chr(10).join(report_lines)}

---

# Next Steps (Prioritized)
"""
    if affected:
        # Build dynamic next steps based on what was found
        step_num = 0

        step_num += 1
        report += f"""
## {step_num}. IMMEDIATE: Remove or update litellm
```bash
pip uninstall litellm -y
# or: pip install --upgrade litellm
pip install --upgrade dspy crewai langgraph 2>/dev/null
```
"""
        # Check which credential types were present and add targeted rotation steps
        present_descs = [d for d, p, t in present]

        if any("SSH" in d for d in present_descs):
            step_num += 1
            report += f"""
## {step_num}. URGENT: Rotate SSH keys
```bash
cp -r ~/.ssh ~/.ssh.backup.$(date +%s)
ssh-keygen -t ed25519 -C "your_email@example.com"
gh ssh-key add ~/.ssh/id_ed25519.pub --title "rotated $(date +%Y-%m-%d)"
```
- Remove old public keys from: GitHub, GitLab, Bitbucket, all remote servers
- Update ~/.ssh/config if needed
- Test connectivity: `ssh -T git@github.com`
"""

        if any("AWS" in d for d in present_descs):
            step_num += 1
            report += f"""
## {step_num}. URGENT: Rotate AWS credentials
```bash
aws iam create-access-key
# Update ~/.aws/credentials with the new key
aws iam delete-access-key --access-key-id OLD_KEY_ID
```
- Check CloudTrail for unauthorized access:
```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --start-time "2025-03-20T00:00:00Z" --end-time "2025-03-25T00:00:00Z"
```
- Review IAM activity for any new users, roles, or policies created
"""

        if any("GCP" in d for d in present_descs):
            step_num += 1
            report += f"""
## {step_num}. URGENT: Rotate GCP credentials
```bash
gcloud auth revoke --all
gcloud auth login
gcloud auth application-default login
```
- Review GCP Audit Logs for unauthorized activity
- Rotate any service account keys
"""

        if any("Azure" in d for d in present_descs):
            step_num += 1
            report += f"""
## {step_num}. URGENT: Rotate Azure credentials
```bash
az logout
az login
```
- Review Azure Activity Log for unauthorized access
- Rotate any service principal secrets
"""

        if any("Kubernetes" in d for d in present_descs):
            step_num += 1
            report += f"""
## {step_num}. URGENT: Rotate Kubernetes credentials
```bash
# Re-authenticate to your cluster
# For GKE:
gcloud container clusters get-credentials CLUSTER_NAME --zone ZONE
# For EKS:
aws eks update-kubeconfig --name CLUSTER_NAME --region REGION
```
- Check for unauthorized pods, deployments, or RBAC changes
- Review Kubernetes audit logs
"""

        if any("Git" in d for d in present_descs):
            step_num += 1
            report += f"""
## {step_num}. Rotate Git credentials
```bash
git config --global --list
git config --global credential.helper
```
- Revoke and regenerate GitHub/GitLab personal access tokens
- Check for unauthorized commits or repository access
"""

        step_num += 1
        report += f"""
## {step_num}. Rotate ALL API keys and tokens
Any key that was in your environment or .env files is compromised:
- OpenAI API key — https://platform.openai.com/api-keys
- Anthropic API key — https://console.anthropic.com/settings/keys
- All other LLM provider keys
- Database passwords and connection strings
- NPM tokens (`npm token revoke`)
- PyPI tokens
- Slack/Discord webhooks
- Any CI/CD secrets (GitHub Actions, CircleCI, etc.)

To see which env vars were exposed:
```bash
env | grep -iE 'key|token|secret|password|api|auth' | sed 's/=.*/=***/'
```
"""

        step_num += 1
        report += f"""
## {step_num}. Check shell history for exfiltrated commands
```bash
# Review what was in your history (attacker had access to this)
wc -l ~/.zsh_history ~/.bash_history 2>/dev/null
```
- If history contains passwords or tokens passed as arguments, rotate those too
"""

        step_num += 1
        report += f"""
## {step_num}. Run antivirus / malware scan
```bash
# macOS with ClamAV:
brew install clamav && freshclam && clamscan -r --bell -i ~
```
"""

        step_num += 1
        report += f"""
## {step_num}. FOLLOW-UP: Monitor for unauthorized access
- Watch CloudTrail / GCP Audit Logs / Azure Activity Log for 30 days
- Enable MFA on all accounts if not already done
- Consider enabling AWS GuardDuty or equivalent
- Set up billing alerts for unexpected charges
- Monitor GitHub/GitLab for unauthorized repository access
"""

    else:
        report += """
## No immediate action required

litellm was not detected on this system. However:

1. If you previously had litellm installed and removed it, treat as potentially compromised
   and follow the full rotation steps above.

2. Check any CI/CD environments, Docker containers, or remote servers where litellm
   may have been installed.

3. If you use Cursor IDE, verify your MCP plugins did not pull litellm transitively.

4. As a precaution, consider rotating any API keys that were in environment variables
   during the attack window.
"""

    report += """
---
Generated by litellm-security-checker. When in doubt, assume compromise and rotate everything.
The cost of rotating credentials is far lower than the cost of a breach.
"""

    st.text_area(
        "Full report (select all + copy):",
        value=report,
        height=500,
        key="report_output",
    )

    # Also offer a download button
    st.download_button(
        label="Download report as .md",
        data=report,
        file_name=f"litellm-security-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md",
        mime="text/markdown",
    )

st.divider()
st.caption("Based on public disclosures about the litellm PyPI supply chain compromise. "
           "When in doubt, assume compromise and rotate everything.")
