"""
PHI Encryption Missing Rule

Detects patient health information (PHI) fields in Eloquent models that are
not cast as `encrypted` or `encrypted:array`. In HIPAA-regulated applications,
sensitive patient data fields should be encrypted at rest.

Scans model `$casts` arrays and flags PHI-suggestive field names that lack
encryption casts.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class PhiEncryptionMissingRule(Rule):
    id = "phi-encryption-missing"
    name = "PHI Encryption Missing"
    description = "Detects patient health information fields in models that are not encrypted at rest"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = (
        "Add `'encrypted'` cast to the PHI field in the model's `$casts` array. "
        "For array-type fields use `'encrypted:array'`. "
        "Example:\n"
        "```php\n"
        "protected $casts = [\n"
        "    'ssn' => 'encrypted',\n"
        "    'date_of_birth' => 'encrypted',\n"
        "];\n"
        "```"
    )
    examples = {
        "bad": "protected $casts = ['ssn' => 'string'];",
        "good": "protected $casts = ['ssn' => 'encrypted'];",
    }
    priority = 1
    group = "Security Hardening"
    applies_to = ["model"]
    references = [
        "HIPAA Security Rule §164.312(a)(1)",
        "OWASP Cryptographic Storage Cheat Sheet",
    ]
    related_rules = ["plain-text-sensitive-config"]
    false_positive_notes = (
        "May fire for projects that handle PHI at the database level (TDE, column-level "
        "encryption via DBMS triggers) rather than at the application layer. "
        "Verify your encryption strategy before suppressing."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "phi-encryption"}

    _PHI_FIELDS = re.compile(
        r"("
        r"ssn|social_security|"
        r"date_of_birth|dob|birth_date|birthdate|"
        r"medical_record|mrn|patient_id|"
        r"diagnosis|diagnoses|diagnosis_code|icd_code|"
        r"medication|medications|prescription|"
        r"treatment|procedure|procedure_code|cpt_code|"
        r"lab_result|laboratory|test_result|"
        r"insurance_id|insurance_number|policy_number|claim_id|"
        r"national_id|national_identifier|passport_id|"
        r"health_condition|condition_name|"
        r"clinical_note|progress_note|physician_note|"
        r"phi|protected_health|"
        r"patient_email|patient_phone|patient_address"
        r")",
        re.IGNORECASE,
    )

    _CASTS_BLOCK = re.compile(
        r"(?:protected\s+\$casts\s*=\s*\[)(.*?)(?:\];)",
        re.DOTALL,
    )

    _CAST_ENTRY = re.compile(
        r"['\"]\s*(?P<field>\w+)\s*['\"]\s*=>\s*['\"]"
        r"(?P<cast>[\w:.-]+)"
        r"['\"]",
        re.IGNORECASE,
    )

    _MODEL_PATH_PATTERN = re.compile(r"/models/", re.IGNORECASE)

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        norm = (file_path or "").replace("\\", "/").lower()
        if not self._MODEL_PATH_PATTERN.search(norm) or not norm.endswith(".php"):
            return []
        if "/tests/" in norm or "/vendor/" in norm:
            return []

        casts_block = self._CASTS_BLOCK.search(content)
        if not casts_block:
            return []

        casts_body = casts_block.group(1)

        casted_fields: dict[str, str] = {}
        for entry in self._CAST_ENTRY.finditer(casts_body):
            field = entry.group("field")
            cast = entry.group("cast")
            casted_fields[field.lower()] = cast.lower()

        phi_found_in_casts: dict[str, str] = {}
        for field_name in casted_fields:
            if self._PHI_FIELDS.search(field_name):
                cast_type = casted_fields[field_name]
                phi_found_in_casts[field_name] = cast_type

        if not phi_found_in_casts:
            return []

        unencrypted = {
            field: cast
            for field, cast in phi_found_in_casts.items()
            if not cast.startswith("encrypted")
        }

        if not unencrypted:
            return []

        field_list = ", ".join(unencrypted.keys())
        model_match = re.search(r"class\s+(\w+)\s+extends\s+\S*Model\b", content)
        model_name = model_match.group(1) if model_match else file_path.rsplit("/", 1)[-1].replace(".php", "")

        return [
            self.create_finding(
                title="PHI field missing encryption cast",
                context=f"{model_name}::casts [{field_list}]",
                file=file_path,
                line_start=1,
                description=(
                    f"Model `{model_name}` declares PHI-suggestive fields (`{field_list}`) "
                    f"in `$casts` but uses `{list(unencrypted.values())[0]}` cast instead of "
                    f"`encrypted`. PHI data should be encrypted at rest."
                ),
                why_it_matters=(
                    "HIPAA requires encryption of protected health information at rest. "
                    "Plaintext PHI in the database is a compliance violation."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.78,
                tags=["laravel", "security", "hipaa", "phi", "encryption"],
                evidence_signals=[
                    f"phi_fields={','.join(unencrypted.keys())}",
                    f"model={model_name}",
                    "encrypted_at_rest=false",
                ],
            ),
        ]
