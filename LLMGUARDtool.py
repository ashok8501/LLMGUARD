import re
import html
import json
import requests
import os

from dotenv import load_dotenv

# ====================================================
# LOAD ENV
# ====================================================
load_dotenv()

# ====================================================
# LLM GUARD IMPORTS
# ====================================================
from llm_guard.input_scanners import (
    Toxicity,
    PromptInjection,
    Anonymize,
)

from llm_guard.output_scanners import (
    Toxicity as OutputToxicity
)

from llm_guard.vault import Vault


class SecureAIPipeline:

    def __init__(self):

        # ====================================================
        # API KEY
        # ====================================================
        self.API_KEY = os.getenv(
            "GROQ_API_KEY"
        )

        if not self.API_KEY:
            raise ValueError(
                "GROQ_API_KEY not found in .env"
            )

        # ====================================================
        # GROQ URL
        # ====================================================
        self.URL = (
            "https://api.groq.com/openai/v1/chat/completions"
        )

        # ====================================================
        # VALIDATION SETTINGS
        # ====================================================
        self.max_length = 500

        self.allowed_pattern = re.compile(
            r"^[a-zA-Z0-9\s.,!?@#%&()_\-+=:/'\"]+$"
        )

        # ====================================================
        # ATTACK PATTERNS
        # ====================================================
        self.block_patterns = [

            # SQL Injection
            r"drop\s+table",
            r"union\s+select",
            r"delete\s+from",
            r"insert\s+into",

            # Command Injection
            r"rm\s+-rf",
            r"shutdown",
            r"exec\s*\(",
            r"system\s*\(",
            r"wget\s+http",
            r"curl\s+http",

            # Path Traversal
            r"\.\./",
            r"\.\.\\",

            # XSS
            r"<script.*?>.*?</script>",
        ]

        # ====================================================
        # DANGEROUS KEYWORDS
        # ====================================================
        self.dangerous_keywords = [
  
           
            "nuclear bomb",
            "make explosive",
            "terrorist attack",
            "how to kill",
            "how to hack",
            "steal password",
            "credit card fraud",
        ]

        # ====================================================
        # LLM GUARD SCANNERS
        # ====================================================
        self.toxicity_scanner = Toxicity()

        self.injection_scanner = (
            PromptInjection()
        )

        self.sensitive_scanner = (
            Anonymize(vault=Vault())
        )

        self.output_scanner = (
            OutputToxicity()
        )

    # ====================================================
    # SANITIZE INPUT
    # ====================================================
    def sanitize_input(self, text):

        # Decode HTML
        text = html.unescape(text)

        # Remove Script Tags
        text = re.sub(
            r"<script.*?>.*?</script>",
            "",
            text,
            flags=re.IGNORECASE | re.DOTALL
        )

        # Remove iframe
        text = re.sub(
            r"<iframe.*?>.*?</iframe>",
            "",
            text,
            flags=re.IGNORECASE | re.DOTALL
        )

        # Remove javascript:
        text = re.sub(
            r"javascript:",
            "",
            text,
            flags=re.IGNORECASE
        )

        # Remove HTML Tags
        text = re.sub(
            r"<[^>]+>",
            "",
            text
        )

        # Remove Dangerous Symbols
        text = re.sub(
            r"[<>`;$]",
            "",
            text
        )

        # Normalize Spaces
        text = re.sub(
            r"\s+",
            " ",
            text
        )

        return text.strip()

    # ====================================================
    # VALIDATE INPUT
    # ====================================================
    def validate_input(self, text):

        if not text.strip():
            return False, "Input Empty"

        if len(text) > self.max_length:
            return False, "Input Too Long"

        if not self.allowed_pattern.match(text):
            return False, (
                "Invalid Characters Detected"
            )

        return True, "Validation Passed"

    # ====================================================
    # ATTACK DETECTION
    # ====================================================
    def detect_attacks(self, text):

        detected = []

        for pattern in self.block_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE
            ):
                detected.append(pattern)

        return detected

    # ====================================================
    # DANGEROUS KEYWORD DETECTION
    # ====================================================
    def detect_dangerous_keywords(
        self,
        text
    ):

        detected = []

        text_lower = text.lower()

        safe_words = [
            "prevent",
            "awareness",
            "education",
            "history",
            "avoid",
        ]

        if any(
            word in text_lower
            for word in safe_words
        ):
            return []

        for keyword in self.dangerous_keywords:

            if keyword in text_lower:
                detected.append(keyword)

        return detected

    # ====================================================
    # INPUT SECURITY PIPELINE
    # ====================================================
    def secure_input(self, prompt):

        print(
            "\n========== ORIGINAL INPUT =========="
        )

        print(prompt)

        issues_found = False

        # ====================================================
        # STEP 1 -> SANITIZATION
        # ====================================================
        sanitized = self.sanitize_input(
            prompt
        )

        print(
            "\n========== SANITIZED INPUT =========="
        )

        print(sanitized)

        # ====================================================
        # STEP 2 -> VALIDATION
        # ====================================================
        valid, message = self.validate_input(
            sanitized
        )

        print(
            "\n========== VALIDATION =========="
        )

        print("Status :", valid)
        print("Message:", message)

        if not valid:

            print(
                "\n❌ INPUT VALIDATION FAILED"
            )

            return None

        # ====================================================
        # STEP 3 -> ATTACK DETECTION
        # ====================================================
        detected_attacks = (
            self.detect_attacks(sanitized)
        )

        print(
            "\n[Attack Detection]"
        )

        if detected_attacks:

            for attack in detected_attacks:

                print(
                    f"❌ Attack Pattern Detected : {attack}"
                )

            issues_found = True

        else:
            print("✅ No Attack Detected")

        # ====================================================
        # STEP 4 -> DANGEROUS KEYWORD SCAN
        # ====================================================
        dangerous_keywords = (
            self.detect_dangerous_keywords(
                sanitized
            )
        )

        print(
            "\n[Dangerous Keyword Scan]"
        )

        if dangerous_keywords:

            for keyword in dangerous_keywords:

                print(
                    f"❌ Dangerous Keyword : {keyword}"
                )

            issues_found = True

        else:
            print("✅ No Dangerous Keywords")

        # ====================================================
        # STEP 5 -> TOXICITY SCAN
        # ====================================================
        clean, valid, score = (
            self.toxicity_scanner.scan(
                sanitized
            )
        )

        print(
            "\n[Toxicity Scan]"
        )

        print("Valid :", valid)
        print("Risk  :", score)

        if not valid:

            print(
                "❌ Toxic Content Detected"
            )

            issues_found = True

        else:
            print("✅ No Toxicity")

        # ====================================================
        # STEP 6 -> PROMPT INJECTION
        # ====================================================
        clean, valid, score = (
            self.injection_scanner.scan(
                clean
            )
        )

        print(
            "\n[Prompt Injection Scan]"
        )

        print("Valid :", valid)
        print("Risk  :", score)

        if not valid:

            print(
                "❌ Prompt Injection Detected"
            )

            issues_found = True

        else:
            print("✅ No Prompt Injection")

        # ====================================================
        # STEP 7 -> PII DETECTION
        # ====================================================
        clean, valid, score = (
            self.sensitive_scanner.scan(
                clean
            )
        )

        print(
            "\n[Sensitive Data Scan]"
        )

        print("Valid :", valid)
        print("Risk  :", score)

        print("Sanitized :", clean)

        if score > 0:

            print(
                "❌ Sensitive Data Detected"
            )

            issues_found = True

        else:
            print("✅ No Sensitive Data")

        # ====================================================
        # FINAL RESULT
        # ====================================================
        if issues_found:

            print(
                "\n❌ INPUT BLOCKED DUE TO SECURITY RISKS"
            )

            return None

        print(
            "\n✅ INPUT IS SAFE"
        )

        return clean

    # ====================================================
    # SEND TO GROQ
    # ====================================================
    def send_to_llm(self, safe_prompt):

        headers = {

            "Authorization":
                f"Bearer {self.API_KEY}",

            "Content-Type":
                "application/json"
        }

        data = {

            "model":
                "llama-3.1-8b-instant",

            "messages": [
                {
                    "role": "user",
                    "content": safe_prompt
                }
            ],

            "temperature": 0.7,
            "max_tokens": 300
        }

        response = requests.post(
            self.URL,
            headers=headers,
            data=json.dumps(data)
        )

        result = response.json()

        return (
            result["choices"][0]
            ["message"]["content"]
        )

    # ====================================================
    # OUTPUT VALIDATION
    # ====================================================
    def validate_output(self, output):

        if not output.strip():
            return False, "Empty Output"

        if len(output) > 5000:
            return False, "Output Too Long"

        return True, "Output Valid"

    # ====================================================
    # SANITIZE OUTPUT
    # ====================================================
    def sanitize_output(self, output):

        output = re.sub(
            r"<script.*?>.*?</script>",
            "",
            output,
            flags=re.IGNORECASE | re.DOTALL
        )

        output = re.sub(
            r"<[^>]+>",
            "",
            output
        )

        output = re.sub(
            r"[<>`;$]",
            "",
            output
        )

        output = re.sub(
            r"\s+",
            " ",
            output
        )

        return output.strip()

    # ====================================================
    # OUTPUT SECURITY
    # ====================================================
    def secure_output(
        self,
        prompt,
        output
    ):

        print(
            "\n========== OUTPUT SECURITY =========="
        )

        # ====================================================
        # OUTPUT VALIDATION
        # ====================================================
        valid, message = self.validate_output(
            output
        )

        print(
            "\n[Output Validation]"
        )

        print("Status :", valid)
        print("Message:", message)

        if not valid:

            print(
                "\n❌ INVALID OUTPUT"
            )

            return None

        # ====================================================
        # SANITIZE OUTPUT
        # ====================================================
        sanitized_output = (
            self.sanitize_output(output)
        )

        print(
            "\n[Sanitized Output]"
        )

        print(sanitized_output)

        # ====================================================
        # OUTPUT TOXICITY
        # ====================================================
        safe_output, valid, score = (
            self.output_scanner.scan(
                prompt,
                sanitized_output
            )
        )

        print(
            "\n[Output Toxicity Scan]"
        )

        print("Valid :", valid)
        print("Risk  :", score)

        if not valid:

            print(
                "\n❌ UNSAFE OUTPUT BLOCKED"
            )

            return None

        # ====================================================
        # OUTPUT PII
        # ====================================================
        safe_output, valid, score = (
            self.sensitive_scanner.scan(
                safe_output
            )
        )

        print(
            "\n[Output PII Scan]"
        )

        print("Valid :", valid)
        print("Risk  :", score)

        return safe_output


# ====================================================
# MAIN
# ====================================================
if __name__ == "__main__":

    pipeline = SecureAIPipeline()

    while True:

        prompt = input(
            "\nEnter Prompt (type 'exit' to quit): "
        )

        if prompt.lower() == "exit":
            break

        # ====================================================
        # SECURE INPUT
        # ====================================================
        safe_prompt = (
            pipeline.secure_input(prompt)
        )

        if not safe_prompt:
            continue

        try:

            print(
                "\n✅ SENDING TO GROQ..."
            )

            # ====================================================
            # SEND TO LLM
            # ====================================================
            llm_output = (
                pipeline.send_to_llm(
                    safe_prompt
                )
            )

            print(
                "\n========== RAW LLM OUTPUT =========="
            )

            print(llm_output)

            # ====================================================
            # SECURE OUTPUT
            # ====================================================
            final_output = (
                pipeline.secure_output(
                    safe_prompt,
                    llm_output
                )
            )

            if final_output:

                print(
                    "\n========== FINAL SAFE OUTPUT =========="
                )

                print(final_output)

        except Exception as e:

            print(
                "\n❌ API ERROR"
            )

            print(e)