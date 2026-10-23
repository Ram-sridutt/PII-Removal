# PII-Removal
Personal Information removal from clinical documents. 

This project implements a robust, automated two-pass clinical de-identification pipeline. It is designed to process unstructured medical reports (e.g., SOAP notes, consults, discharge summaries) and maximize PII/PHI redaction while preserving the readability of clinical terminology. The system enforces HIPAA Safe Harbor compliance (45 CFR § 164.514(b)(2)).

**Prerequisites & Setup:**
Before running the pipeline, you need to set up your Python environment and install the required external libraries.
1. Python VersionEnsure you are using Python 3.11 or newer. The script includes a custom patch to ensure older NLP libraries remain compatible with modern Python regex engines.
2. Required LibrariesOpen your terminal (ensure your virtual environment is active, e.g., (venv)) and run the following command to install the necessary packages:
   pip install philter-ucsf presidio-analyzer presidio-anonymizer nltk
philter-ucsf: The core deterministic rule-based engine built by UCSF.
presidio-analyzer & presidio-anonymizer: Microsoft's contextual NLP engines for finding and masking residual PII.
nltk: The Natural Language Toolkit, used for tokenization and filtering out English stopwords to prevent over-redaction. (Note: The script automatically downloads the specific NLTK data files it needs on the first run).

**How the Pipeline Works**
The code operates in a strict Two-Pass Architecture to balance high-sensitivity PII redaction with the preservation of critical medical data.

PASS 1: UCSF Philter + HIPAA Safe HarborThe first pass relies on deterministic rules, census dictionaries, and coordinate mapping.
Pre-Scanning: The script scans the raw text to locate ages and 5-digit ZIP codes before they get universally masked by Philter's number scrubbers.
Philter Engine execution: UCSF Philter applies over 50 clinical regex files and compares words against the 1990 US Census surname database, replacing identifiers with asterisks (****).
False-Positive Restorer: Because Philter's high-sensitivity rules occasionally over-mask clinical terms (e.g., mistaking the color "White" in "White blood cell" for a surname, or "stat CT" for the state of Connecticut), a coordinate restorer safely unmasks these specific medical acronyms and NLTK stopwords.
HIPAA Safe Harbor Formatting:Ages: Any age $\ge 90$ is clamped to Age: 90+. Ages $\le 89$ are preserved for analytics.
ZIP Codes: 5-digit geographic identifiers are truncated to their 3-digit prefix (e.g., IN 46805 becomes IN 468**), strictly adhering to Safe Harbor requirements.

PASS 2: Microsoft Presidio (Contextual Auditor)
The second pass acts as a safety net for edge cases that bypass dictionary lookups (e.g., rare, non-US-Census surnames, or single-letter initials like "Dr. Y").
Case-Sensitive Role Matching: Presidio is configured with custom, case-sensitive PatternRecognizers. It looks for clinical honorifics and titles (Dr., Attending, Specialist, Nurse) followed by capitalized words or initials.
Verification: It ignores standard clinical grammar and words already masked by Philter.Anonymization: Any residual identifiers caught in this net are replaced with structured tags, such as <PERSON>.

Usage InstructionsPrepare Samples:
Create a folder named samples/ in the same directory as your script (demo.py). Place any raw clinical notes you want to scrub inside this folder as .txt files (e.g., note1.txt).Run the Pipeline:
Execute the batch processor from your terminal:python demo.py
Retrieve Output:
The script will automatically create a redacted_outputs/ folder. For every file in the samples/ folder, a corresponding redacted_filename.txt will be generated here containing the clean, analytics-ready text.
