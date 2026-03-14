# CISO Backup Generator

A web app that merges applied controls and vulnerabilities into a CISO Assistant backup file.

## Usage

```bash
docker compose up --build
```

Open `http://localhost:8080`, upload the three files, and click **Generate Backup** to download the merged `.bak` file.

## Input Files

Download blank templates from the app's home page.

### Applied Controls (`.xlsx`)

Two sheets required: **Level1** and **Level2** — both use the same columns.

| Control ID | Requirement | Config Setting | Category | Priority | CSF Function | Effort | Impact |
|---|---|---|---|---|---|---|---|
| AC.1.001 | Limit system access to authorized users | Enable MFA for all user accounts | Technical | P1 | Protect | Low | High |
| AC.1.002 | Limit system access to types of transactions | Configure role-based access control | Organizational | P2 | Protect | Medium | High |
| IR.2.093 | Track and document incidents | Deploy SIEM and incident log retention | Technical | P1 | Detect | High | High |

**Accepted values:**

| Column | Accepted Values |
|---|---|
| Category | `Technical`, `Policy`, `Organizational` |
| Priority | `P1`, `P2`, `P3` |
| CSF Function | `Identify`, `Protect`, `Detect`, `Respond`, `Recover`, `Govern` |
| Effort | `Low`, `Medium`, `High` |
| Impact | `Low`, `Medium`, `High` |

### Vulnerabilities (`.xlsx`)

Single sheet with the following columns.

| Ref ID | Name | Description | Annotation |
|---|---|---|---|
| CVE-2024-1234 | Unpatched OpenSSL | OpenSSL 1.x on web servers lacks critical security patches | Discovered during Q1 scan |
| VULN-0042 | Weak Password Policy | Password policy does not enforce minimum length or complexity | Internal audit finding |
| CVE-2023-9999 | Log4Shell Exposure | Legacy Java service uses vulnerable Log4j version | Vendor patch pending |

### Source Backup (`.bak`)

The existing CISO Assistant backup file (plain JSON or gzipped). Must contain a `Global` folder in the data.

## Output

A gzipped `.bak` file named `backup-YYYY-MM-DD.bak`, ready to import into CISO Assistant.
