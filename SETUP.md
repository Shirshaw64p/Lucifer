# Lucifer — Reporting Engine Setup Guide

## System Requirements

| Requirement | Minimum Version |
|------------|----------------|
| Python | 3.11+ (3.12 recommended) |
| pip | 23+ |
| OS | Linux, macOS, or Windows (WSL recommended for WeasyPrint) |

## Python Dependencies

Install all reporting-engine dependencies:

```bash
pip install pyyaml pydantic jinja2 cvss weasyprint pytest
```

### Dependency Reference

| Package | Purpose |
|---------|---------|
| `pyyaml` | YAML parser for compliance rules |
| `pydantic` | Data models and validation |
| `jinja2` | HTML template rendering |
| `cvss` | CVSS 3.1 vector calculation |
| `weasyprint` | HTML → PDF conversion |
| `pytest` | Test runner |

## WeasyPrint System Dependencies

WeasyPrint requires native libraries that must be installed at the OS level
**before** `pip install weasyprint` will function correctly.

### Linux (Debian / Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y \
    libcairo2 \
    libcairo2-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-liberation \
    fonts-dejavu-core
```

### Linux (RHEL / Fedora / CentOS)

```bash
sudo dnf install -y \
    cairo \
    cairo-devel \
    pango \
    pango-devel \
    gdk-pixbuf2 \
    libffi-devel \
    shared-mime-info \
    liberation-fonts \
    dejavu-sans-fonts
```

### macOS

```bash
brew install cairo pango gdk-pixbuf libffi
```

### Windows

WeasyPrint on native Windows requires GTK3:

1. Install [MSYS2](https://www.msys2.org/)
2. In MSYS2 terminal:
   ```bash
   pacman -S mingw-w64-x86_64-pango mingw-w64-x86_64-cairo mingw-w64-x86_64-gdk-pixbuf2
   ```
3. Add `C:\msys64\mingw64\bin` to your system `PATH`.

**Recommended:** Use WSL2 (Ubuntu) for the simplest experience on Windows.

## Running Tests

From the project root:

```bash
# Run all reporting-engine tests
python -m pytest reports/tests/ -v

# Run a specific test file
python -m pytest reports/tests/test_compliance_engine.py -v

# Run with coverage
pip install pytest-cov
python -m pytest reports/tests/ --cov=reports --cov-report=term-missing
```

## Quick Verification

```bash
# Verify imports work
python -c "from reports.compliance_engine import ComplianceEngine; print('OK')"
python -c "from reports.cvss_scorer import CVSSScorer; print('OK')"
python -c "from reports.pdf_renderer import PDFRenderer; print('OK')"
python -c "from reports.report_assembler import ReportAssembler; print('OK')"
python -c "from reports.deduplicator import FindingDeduplicator; print('OK')"
```

## Directory Structure

```
reports/
├── __init__.py
├── models.py                  # Pydantic data models
├── compliance_rules.yaml      # YAML mapping → 18 categories × 4 frameworks
├── compliance_engine.py       # ComplianceEngine class
├── cvss_scorer.py             # CVSSScorer class
├── pdf_renderer.py            # PDFRenderer (WeasyPrint)
├── report_assembler.py        # ReportAssembler orchestrator
├── deduplicator.py            # FindingDeduplicator
├── templates/
│   ├── base.html              # Global styles, header/footer, CSS vars
│   ├── cover.html             # Cover page
│   ├── executive_summary.html # Risk rating + top findings
│   ├── attack_narrative.html  # Chronological narrative
│   ├── finding_detail.html    # Reusable per-finding partial
│   ├── findings_list.html     # Iterates finding_detail
│   ├── evidence_appendix.html # Screenshots + HAR transcripts
│   ├── asset_inventory.html   # Discovered assets table
│   ├── compliance_matrix.html # Control-by-control status table
│   └── remediation_roadmap.html # Priority-ordered remediation table
├── tests/
│   ├── __init__.py
│   ├── test_compliance_engine.py
│   ├── test_cvss_scorer.py
│   ├── test_pdf_renderer.py
│   └── test_deduplicator.py
└── output/                    # Generated PDFs (created at runtime)
```
