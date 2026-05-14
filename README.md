# Automated Multi-Browser Forensic Analysis Tool

A Python-based browser forensic analysis tool designed for digital investigations across Google Chrome, Microsoft Edge, and Mozilla Firefox.

## Features
- Multi-browser artifact acquisition
- Live and dead acquisition support
- SHA-256 hash verification
- Unified timeline reconstruction
- Anti-forensics detection
- Deleted history recovery using SQLite carving
- DNS cache analysis
- Chain of custody generation
- Interactive forensic dashboard

## Technologies Used
- Python
- SQLite
- HTML/CSS/JavaScript
- Windows Volume Shadow Copy Service (VSS)

## Supported Browsers
- Google Chrome
- Microsoft Edge
- Mozilla Firefox

## Project Structure
- `acquisition.py` → Dead acquisition
- `live_acquisition.py` → Live acquisition using VSS
- `parser.py` → SQLite artifact extraction
- `timeline.py` → Timeline and session analysis
- `recover_deleted.py` → Deleted record recovery
- `dns_parser.py` → DNS cache analysis
- `dashboard.py` → Interactive dashboard generation
- `chain_of_custody.py` → Evidence integrity documentation

## Installation
```bash
pip install -r requirements.txt
```

## Run
```bash
python app.py
```

## Screenshots
(Add screenshots here)

## Disclaimer
This project was developed for academic and educational purposes in the field of digital forensics and cybersecurity.
