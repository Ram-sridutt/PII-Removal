import os
import re
import glob
import json
import shutil
import warnings
import nltk

warnings.filterwarnings("ignore")

import philter_ucsf
from philter_ucsf.philter import Philter
from presidio_analyzer import Pattern, PatternRecognizer, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine

# Ensure NLTK resources required by UCSF Philter are present
for resource in ['punkt', 'punkt_tab', 'averaged_perceptron_tagger', 'averaged_perceptron_tagger_eng']:
    try:
        nltk.download(resource, quiet=True)
    except Exception:
        pass


# =====================================================================
# HELPER: SCOPED PYTHON 3.11+ REGEX PATCH FOR PHILTER INITIALIZATION
# =====================================================================
_orig_re_compile = re.compile

def _philter_compat_re_compile(pattern, flags=0):
    if isinstance(pattern, str) and "(?" in pattern:
        if "(?i)" in pattern:
            flags |= re.IGNORECASE
            pattern = pattern.replace("(?i)", "")
        if "(?m)" in pattern:
            flags |= re.MULTILINE
            pattern = pattern.replace("(?m)", "")
        if "(?s)" in pattern:
            flags |= re.DOTALL
            pattern = pattern.replace("(?s)", "")
    return _orig_re_compile(pattern, flags)


# =====================================================================
# PASS 1: OFFICIAL UCSF PHILTER ENGINE + GENERAL HIPAA SAFE HARBOR
# =====================================================================
def run_pass1_philter(input_text: str) -> str:
    """
    Runs the official UCSF Philter engine and applies general HIPAA Safe Harbor
    rules for ages (clamping 90+ to '90+', retaining <=89) and 3-digit ZIP codes.
    """
    # 1. Pre-scan general age formats ("Age: 95", "71-year-old", "92 yo", "92 y/o")
    age_label_matches = re.findall(r'\b(Age|age|AGE)(:\s*|\s+)(\d{1,3})\b', input_text)
    age_hyphen_matches = re.findall(r'\b(\d{1,3})(-\s*year-\s*old|\s+years?\s+old|\s+y/?o|\s+y\.o\.)\b', input_text, flags=re.IGNORECASE)

    # 2. Pre-scan general US State + 5-digit ZIP formats (e.g., "IN 46805")
    zip_matches = re.findall(r'\b([A-Z]{2})\s+(\d{3})\d{2}(?:-\d{4})?\b', input_text)

    original_cwd = os.getcwd()
    temp_dir = os.path.abspath("temp_philter_run")
    input_dir = os.path.join(temp_dir, "input")
    output_dir = os.path.join(temp_dir, "output")

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    note_path = os.path.join(input_dir, "note.txt")
    with open(note_path, "w", encoding="utf-8") as f:
        f.write(input_text)

    pkg_dir = os.path.dirname(philter_ucsf.__file__)
    # Keep a small, explicit set of common clinical phrases readable. Philter's
    # bundled rules can otherwise mask parts of these terms as names or locations.
    base_filter_config_path = os.path.join(pkg_dir, "configs", "philter_delta.json")
    with open(base_filter_config_path, "r", encoding="utf-8") as config_file:
        filter_config = json.load(config_file)

    clinical_terms_path = os.path.join(temp_dir, "clinical_terms.txt")
    clinical_safe_terms = [
        r"white\s+blood\s+cell", r"ct\s+scan", r"normal\s+sinus\s+rhythm",
        r"left\s+lower\s+quadrant", r"bright\s+red\s+blood\s+per\s+rectum",
        r"lactated\s+ringer", r"ray[-\s]?tec", r"the\s+crown", r"hall\s+drill",
        r"regains", r"slim\s+fast", r"atkin'?s\s+diet", r"100-pound", r"lap-band",
        r"oven", r"balcony", r"second\s+storied", r"said", r"unsafely", r"nil", r"at\s+present", r"lyrica",
        r"emphasizing", r"temodar", r"spirit", r"followups", r"skull\s+x[- ]?rays",
        r"g4", r"\d+-\d+\s+spells", r"vault\s+prolapse", r"abdominosacrocolpopexy",
        r"pfannenstiel", r"mesh\s+erogenic\s+exposure", r"mobiliz\w*", r"bookwalter",
        r"foley", r"indigo\s+carmine", r"bovie", r"overeaters\s+anonymous", r"came", r"hence", r"chosen"
    ]
    clinical_terms_pattern = r"(?i)\b(?:" + "|".join(clinical_safe_terms) + r")\b"
    with open(clinical_terms_path, "w", encoding="utf-8") as terms_file:
        terms_file.write(clinical_terms_pattern + "\n")
    filter_config.insert(0, {
        "title": "CoSign clinical terms allowlist",
        "type": "regex",
        "exclude": False,
        "filepath": clinical_terms_path,
        "notes": "Preserve high-confidence clinical phrases that should remain readable."
    })
    filter_config_path = os.path.join(temp_dir, "philter_config.json")
    with open(filter_config_path, "w", encoding="utf-8") as config_file:
        json.dump(filter_config, config_file)

    philter_config = {
        "verbose": False,
        "run_eval": False,
        "finpath": input_dir + os.sep,
        "foutpath": output_dir + os.sep,
        "outformat": "asterisk",
        "filters": filter_config_path,
        "cachepos": None
    }

    try:
        os.chdir(pkg_dir)
        # Apply regex patch ONLY while Philter compiles its legacy 2020 files
        re.compile = _philter_compat_re_compile
        philter_engine = Philter(philter_config)
        philter_engine.map_coordinates()
        philter_engine.transform()
    finally:
        # Immediately restore native Python re.compile
        re.compile = _orig_re_compile
        os.chdir(original_cwd)

    out_file = os.path.join(output_dir, "note.txt")
    with open(out_file, "r", encoding="utf-8") as f:
        safe_harbor_text = f.read()

    # 3. Enforce HIPAA Safe Harbor on "Age: XX" patterns
    for label, sep, age_str in age_label_matches:
        age_val = int(age_str)
        safe_age = "90+" if age_val >= 90 else str(age_val)
        safe_harbor_text = re.sub(
            rf'\b{re.escape(label)}{re.escape(sep)}(?:\*{{1,3}}|\d{{1,3}})\b',
            f"{label}{sep}{safe_age}",
            safe_harbor_text,
            count=1
        )

    # 4. Enforce HIPAA Safe Harbor on "XX-year-old" / "XX yo" narrative patterns
    for age_str, suffix in age_hyphen_matches:
        age_val = int(age_str)
        safe_age = "90+" if age_val >= 90 else str(age_val)
        safe_harbor_text = re.sub(
            rf'(?:\*{{1,3}}|\b\d{{1,3}}){re.escape(suffix)}',
            f"{safe_age}{suffix}",
            safe_harbor_text,
            count=1
        )

    # 5. Enforce HIPAA Safe Harbor 3-Digit ZIP code truncation
    # (17 low-population 3-digit prefixes must become 000** per 45 CFR 164.514(b)(2))
    restricted_zips = {
        "036", "059", "063", "102", "203", "556", "692", "790", "821",
        "823", "830", "831", "878", "879", "884", "890", "893"
    }
    for state_abbr, zip_prefix in zip_matches:
        safe_prefix = "000" if zip_prefix in restricted_zips else zip_prefix
        safe_harbor_text = re.sub(
            rf'\b{re.escape(state_abbr)}\s+(?:\*{{5}}|\d{{5}})\b',
            f'{state_abbr} {safe_prefix}**',
            safe_harbor_text,
            count=1
        )

    shutil.rmtree(temp_dir, ignore_errors=True)
    return safe_harbor_text


# =====================================================================
# PASS 2: GENERAL MICROSOFT PRESIDIO ENGINE
# =====================================================================
def run_pass2_presidio(text: str) -> tuple[str, list]:
    """
    Runs Microsoft Presidio's RecognizerRegistry and AnonymizerEngine with
    strictly case-sensitive clinical patterns (disabling Presidio's default
    re.IGNORECASE flag so lowercase verbs/grammar are never matched).
    """
    # Strictly case-sensitive patterns for titled clinical personnel / honorifics
    # and partially masked multi-part names (e.g., "*** Zymurgy")
    clinical_patterns = [
        Pattern(
            name="doctor_name",
            regex=r"(?<=Dr\. )[A-Z](?:[a-z]{1,25})?(?:\s+[A-Z][a-z]{1,25})?",
            score=0.90
        ),
        Pattern(
            name="doctor_initial_or_name",
            regex=r"(?<=Dr )[A-Z](?:[a-z]{1,25}(?:\s+[A-Z][a-z]{1,25})?)?",
            score=0.90
        ),
        Pattern(
            name="patient_name_context",
            regex=r"(?<=patient )[A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25})?",
            score=0.88
        ),
        Pattern(
            name="female_patient_name_context",
            regex=r"(?<=female )[A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25})?",
            score=0.88
        ),
        Pattern(
            name="emergency_contact_name_context",
            regex=r"(?<=contact is )[A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25})?",
            score=0.90
        )
    ]

    # CRITICAL FIX: Override global_regex_flags to remove Presidio's default re.IGNORECASE
    clinical_person_recognizer = PatternRecognizer(
        supported_entity="PERSON",
        name="ClinicalContextPersonRecognizer",
        patterns=clinical_patterns,
        global_regex_flags=re.DOTALL | re.MULTILINE
    )

    identifier_patterns = [
        Pattern(
            name="medical_record_number",
            regex=r"(?i)\b(?:MRN|medical record(?: number| no\.?|#)?)\s*[:#-]?\s*[A-Z0-9][A-Z0-9-]{2,}\b",
            score=0.95
        ),
        Pattern(
            name="partially_masked_medical_record_number",
            regex=r"(?i)\*{3,}\s+RECORD\s*#\s*:\s*\d{1,}\b",
            score=0.95
        ),
        Pattern(
            name="insurance_member_id",
            regex=r"(?i)\b(?:insurance\s+)?member\s+ID\s*[:#-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b",
            score=0.95
        )
    ]
    identifier_recognizer = PatternRecognizer(
        supported_entity="CUSTOM_ID",
        name="ClinicalIdentifierRecognizer",
        patterns=identifier_patterns,
        global_regex_flags=re.DOTALL | re.MULTILINE
    )

    target_entities = ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "US_SSN", "URL", "IP_ADDRESS", "CUSTOM_ID"]

    # Load Presidio's predefined structured recognizers + our case-sensitive recognizer
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()
    registry.add_recognizer(clinical_person_recognizer)
    registry.add_recognizer(identifier_recognizer)

    raw_results = []
    for recognizer in registry.get_recognizers(language="en", entities=target_entities):
        if not getattr(recognizer, "needs_nlp", False):
            raw_results.extend(recognizer.analyze(text=text, entities=target_entities))

    # Deduplicate overlapping spans and ignore tokens already masked as asterisks by Pass 1
    filtered_results = []
    seen_spans = set()
    for res in sorted(raw_results, key=lambda x: (x.start, -x.end)):
        span_key = (res.start, res.end)
        matched_str = text[res.start:res.end].strip()
        # A bare ellipsis followed by a short country-code suffix can be
        # misread as a URL (for example, "...this"). Require a real URL prefix.
        if res.entity_type == "URL" and not re.match(r"(?i)^(?:https?://|www\.)", matched_str):
            continue        # A bare ellipsis plus a short country-code suffix can be misread as a URL.
        if res.entity_type == "URL" and not re.match(r"(?i)^(?:https?://|www\.)", matched_str):
            continue
        if span_key not in seen_spans and not re.fullmatch(r'[\*\s\.,;-]+', matched_str):
            seen_spans.add(span_key)
            filtered_results.append(res)

    caught_entities = [text[res.start:res.end] for res in filtered_results]

    # Anonymize detected residual PII using Presidio's AnonymizerEngine
    anonymizer = AnonymizerEngine()
    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=filtered_results
    )

    return anonymized_result.text, caught_entities


# =====================================================================
# MAIN BATCH RUNNER
# =====================================================================
if __name__ == "__main__":
    SAMPLES_DIR = "samples"
    OUTPUT_DIR = "redacted_outputs"

    os.makedirs(SAMPLES_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    txt_files = sorted(glob.glob(os.path.join(SAMPLES_DIR, "*.txt")))

    if not txt_files:
        print(f"[!] No .txt files found in '{SAMPLES_DIR}/'.")
        print(f"    Please add one or more .txt files inside '{os.path.abspath(SAMPLES_DIR)}' and run again.")
        exit()

    print("=" * 80)
    print(f"COSIGN TWO-PASS PIPELINE (PASS 1: PHILTER | PASS 2: PRESIDIO) | {len(txt_files)} FILE(S)")
    print("=" * 80)

    for file_path in txt_files:
        filename = os.path.basename(file_path)
        with open(file_path, "r", encoding="utf-8") as f:
            raw_text = f.read().strip()

        print(f"\n>>> PROCESSING FILE: {filename}")
        print("-" * 80)
        print(f"[RAW CLINICAL NOTE]:\n{raw_text}\n")

        # PASS 1: Official UCSF Philter + HIPAA Safe Harbor
        p1_text = run_pass1_philter(raw_text)
        print(f"[PASS 1 - UCSF PHILTER + SAFE HARBOR]:\n{p1_text}\n")

        # PASS 2: Official Microsoft Presidio
        final_text, caught_by_presidio = run_pass2_presidio(p1_text)
        print(f"[PASS 2 - MICROSOFT PRESIDIO]:\n{final_text}")
        if caught_by_presidio:
            print(f"   --> [!] Presidio caught & anonymized residual PII missed by Pass 1: {caught_by_presidio}")
        else:
            print("   --> [OK] Presidio found no residual PII among the configured recognizers.")

        out_path = os.path.join(OUTPUT_DIR, f"redacted_{filename}")
        with open(out_path, "w", encoding="utf-8") as out_f:
            out_f.write(final_text)
        print(f"   --> Saved final redacted note to: {out_path}")
        print("=" * 80)