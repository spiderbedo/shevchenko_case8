# developers: Shevchenko Anna, Komissarov Platon, Loseva Ekaterina, Greshnova Sonya
import re
import base64
import codecs
import ru_local as ru


def find_and_validate_credit_cards(text) -> dict:
    """
    Find and validate credit card numbers in the text using the Luhn algorithm.
    Args:
        text (str): Input text to analyze.
    Returns:
        dict: A dictionary with keys 'valid' and 'invalid' containing lists of card numbers
    """

    pattern = r'(?:\d[\d\-_ ]{14,}\d)'
    candidates = re.findall(pattern, text)
    numbers = []

    for candidate in candidates:
        clean_num = ''.join(c for c in candidate if c.isdigit())
        for i in range(len(clean_num) - 15):
            num = clean_num[i:i + 16]
            if len(num) == 16:
                numbers.append(num)

    valid = []
    invalid = []

    for card in set(numbers):

        digits = [int(d) for d in card]
        for i in range(14, -1, -2):
            doubled = digits[i] * 2
            if doubled > 9:
                doubled -= 9
            digits[i] = doubled

        if sum(digits) % 10 == 0:
            valid.append(card)
        else:
            invalid.append(card)

    return {"valid": valid, "invalid": invalid}


def find_secrets(text) -> list:
    """
    Find potential secrets such as API keys, tokens, and passwords in the text.
    Args:
        text (str): Input text to analyze.
    Returns:
        list: A list of found secrets.
    """

    secrets = []
    patterns = [

        r'sk_live_[a-zA-Z0-9]{10,30}',
        r'pk_test_[a-zA-Z0-9]{10,30}',
        r'sk_test_[a-zA-Z0-9]{10,30}',
        r'pk_live_[a-zA-Z0-9]{10,30}',

        r'[a-zA-Z0-9]{25,40}',

        r'(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]).{8,}',

        r'eyJ[a-zA-Z0-9]{30,}\.[a-zA-Z0-9]{30,}\.[a-zA-Z0-9_-]{30,}',
        r'ghp_[a-zA-Z0-9]{36}',
        r'xoxb-[a-zA-Z0-9-]+',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, text)
        secrets.extend(matches)

    return list(set(secrets))


def find_system_info(text) -> dict:
    """
    Find system information such as IP addresses, file names, and email addresses in the text.
    Args:
        text (str): Input text to analyze.
    Returns:
        dict: A dictionary with keys 'ips', 'files', and 'emails' containing lists of found items.
    """

    result = {'ips': [], 'files': [], 'emails': []}
    ip_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b'
    file_pattern = r'\b[\w-]+\.(?:txt|log|pdf|docx?|xlsx?|jpg|png|config|env|yml|json|sql|bak)\b'
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    result['ips'] = re.findall(ip_pattern, text)
    result['files'] = re.findall(file_pattern, text, re.IGNORECASE)
    result['emails'] = re.findall(email_pattern, text)

    result['ips'] = list(set(result['ips']))
    result['files'] = list(set(result['files']))
    result['emails'] = list(set(result['emails']))

    return result


def decode_messages(text) -> dict:
    """
    Decode messages encoded in Base64, Hex, and ROT13 found in the text.
    Args:
        text (str): Input text to analyze.
    Returns:
        dict: A dictionary with keys 'base64', 'hex', and 'rot13' containing lists of decoded messages.
    """

    result = {'base64': [], 'hex': [], 'rot13': []}
    base64_pattern = r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{4,}(?:={1,2})?(?![A-Za-z0-9+/])'
    hex_pattern = r'(?:0x[a-fA-F0-9]+|\\x[a-fA-F0-9]{2})+'
    rot13_pattern = r'\b[A-Za-z]{4,}\b'

    for match in re.findall(base64_pattern, text):
        try:
            decoded_bytes = base64.b64decode(match)
            decoded_text = decoded_bytes.decode('utf-8')
            if decoded_text.isprintable():
                result['base64'].append(decoded_text)
        except Exception:
            pass

    for match in re.findall(hex_pattern, text):
        hex_string = match
        if hex_string.startswith('0x'):
            hex_string = hex_string[2:]
        hex_string = hex_string.replace('\\x', '')
        try:
            decoded_bytes = bytes.fromhex(hex_string)
            decoded_text = decoded_bytes.decode('utf-8')
            if decoded_text.isprintable():
                result['hex'].append(decoded_text)
        except Exception:
            pass

    for match in re.findall(rot13_pattern, text):
        if len(match) < 4 or not match.isalpha():
            continue
        try:
            decoded_text = codecs.decode(match, 'rot_13')
            if decoded_text != match and decoded_text.isprintable():
                result['rot13'].append(decoded_text)
        except Exception:
            pass

    for key in result:
        result[key] = list(set(result[key]))

    return result


def analyze_logs(text) -> dict:
    """
    Analyze log entries for potential security threats such as SQL injections, XSS attempts,
    suspicious user agents, and failed login attempts.
    Args:
        text (str): Input log text to analyze.
    Returns:
        dict: A dictionary with keys 'sql_injections', 'xss_attempts', 'suspicious_user_agents', and 'failed_logins'
              containing lists of relevant log entries.
    """

    results = {
        'sql_injections': [],
        'xss_attempts': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }

    lines = text.split('\n')

    for line in lines:
        sql_patterns = [
            r"'.*?(OR|AND).*?=.*?",
            r"UNION.*?SELECT",
            r"SELECT.*?FROM",
            r"INSERT.*?INTO",
            r"DROP.*?TABLE",
            r"1['\"]?\\s*OR\\s*['\"]?1",
            r"';.*?--",
            r"OR.*?['\"]?=['\"]?['\"]",
        ]

        for pattern in sql_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                results['sql_injections'].append(line)
                break

        xss_patterns = [
            r"<script.*?>.*?</script>",
            r"alert\s*\(",
            r"onerror\\s*=",
            r"onload\\s*=",
            r"onclick\\s*=",
            r"javascript:",
            r"<iframe.*?>",
            r"<img.*?onerror.*?>",
        ]

        for pattern in xss_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                results['xss_attempts'].append(line)
                break

        suspicious_agents = [
            r"sqlmap",
            r"nikto",
            r"metasploit",
            r"nmap",
            r"wget.*?-.*?--",
            r"curl.*?-.*?--",
            r"havij",
            r"zap",
            r"burp",
            r"EvilBot",
            r"Malicious",
            r"Scanner",
            r"Bot.*?[Mm]alicious",
        ]

        for pattern in suspicious_agents:
            if re.search(pattern, line, re.IGNORECASE):
                results['suspicious_user_agents'].append(line)
                break

        failed_login_patterns = [
            r'\" 401 ',
            r'\" 403 ',
            r'login.*?failed',
            r'authentication.*?failed',
            r'unauthorized',
            r'password.*?incorrect',
            r'invalid.*?credentials',
        ]

        for pattern in failed_login_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                results['failed_logins'].append(line)
                break

    for key in results:
        results[key] = list(set(results[key]))

    return results


def validate_phone(phone) -> tuple:
    """
    Validate and normalize Russian phone numbers to the format +7XXXXXXXXXX.
    Args:
        phone (str): Input phone number string.
    Returns:
        tuple: (is_valid (bool), normalized_number (str))
    """

    digits = ''.join(re.findall(r'\d', phone))

    if len(digits) == 11 and digits[0] in "78":
        normalized = "+7" + digits[1:]
        return True, normalized

    return False, digits


def validate_date(date_str) -> tuple:
    """
    Validate and normalize dates in various formats to "DD.MM.YYYY".
    Args:
        date_str (str): Input date string.
    Returns:
        tuple: (is_valid (bool), normalized_date (str))
    """

    month_ru = {
        "янв": 1, "фев": 2, "мар": 3, "апр": 4, "май": 5, "мая": 5,
        "июн": 6, "июл": 7, "авг": 8, "сен": 9, "окт": 10,
        "ноя": 11, "дек": 12,
        "января": 1, "февраля": 2, "марта": 3, "апреля": 4,
        "июня": 6, "июля": 7, "августа": 8, "сентября": 9,
        "октября": 10, "ноября": 11, "декабря": 12
    }

    months_en = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5,
        "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10,
        "nov": 11, "dec": 12,
        "january": 1, "february": 2, "march": 3, "april": 4,
        "june": 6, "july": 7, "august": 8, "september": 9,
        "october": 10, "november": 11, "december": 12
    }

    date_str = date_str.lower().strip()

    found_month = None
    month_str = None

    for month in month_ru:
        if month in date_str:
            found_month = month_ru[month]
            month_str = month
            break

    if not found_month:
        for month in months_en:
            if month in date_str:
                found_month = months_en[month]
                month_str = month
                break

    if found_month:

        parts = date_str.replace(month_str, "").split()
        numbers = []

        for part in parts:
            clean_num = "".join(c for c in part if c.isdigit())
            if clean_num:
                numbers.append(clean_num)

        if len(numbers) == 2:
            day, year = numbers
            digits = [day, str(found_month), year]
        else:
            return False, date_str

    else:
        digits = []
        current = ""

        for ch in date_str:
            if ch.isdigit():
                current += ch
            elif ch in ".-/" and current:
                if len(current) > 4:
                    return False, date_str
                digits.append(current)
                current = ""

        if current:
            if len(current) > 4:
                return False, date_str
            digits.append(current)

        if len(digits) != 3:
            return False, date_str

    day, month, year = digits

    if len(year) == 2:
        year = "20" + year

    if not (len(day) <= 2 and len(month) <= 2 and len(year) == 4):
        return False, date_str

    day = int(day)
    month = int(month)
    year = int(year)

    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False, date_str

    days_in_month = [31, 29 if (year % 4 == 0 and year % 100 != 0) or year % 400 == 0 else 28,
                     31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    if day > days_in_month[month - 1]:
        return False, date_str

    return True, f"{day}.{month}.{year}"


def validate_inn(inn) -> tuple:
    """
    Validate Russian INN (10 or 12 digits).
    Args:
        inn (str): Input INN string.
    Returns:
        tuple: (is_valid (bool), digits (str))
    """

    n10 = [2, 4, 10, 3, 5, 9, 4, 6, 8]
    n11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    n12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]

    digits = ''.join(re.findall(r'\d', inn))

    if len(digits) not in (10, 12):
        return False, digits

    if len(digits) == 10:
        s = sum(int(digits[i]) * n10[i] for i in range(9))
        check_digit = (s % 11) % 10
        return int(digits[9]) == check_digit, digits
    else:
        s11 = sum(int(digits[i]) * n11[i] for i in range(10))
        check11 = (s11 % 11) % 10
        if int(digits[10]) != check11:
            return False, digits
        s12 = sum(int(digits[i]) * n12[i] for i in range(11))
        check12 = (s12 % 11) % 10
        return int(digits[11]) == check12, digits


def normalize_and_validate(text) -> dict:
    """
    Extract and validate phone numbers, dates, and INNs from the text.
    Args:
        text (str): Input text to analyze.
    Returns:
        dict: A dictionary with keys 'phones', 'dates', and 'inn' containing lists of valid and invalid entries.
    """

    result = {
        "phones": {"valid": [], "invalid": []},
        "dates": {"normalized": [], "invalid": []},
        "inn": {"valid": [], "invalid": []},
        "cards": find_and_validate_credit_cards(text)
    }

    tokens = re.findall(r'[\d\w.\-/()+ ]+', text)

    for token in tokens:

        token = token.strip(" \t\n;:")

        if not any(c.isdigit() for c in token):
            continue

        is_valid, normalized = validate_phone(token)
        if is_valid:
            result["phones"]["valid"].append(normalized)
        elif normalized and 6 <= len(normalized) <= 15:
            result["phones"]["invalid"].append(normalized)

        is_valid, normalized = validate_date(token)
        if is_valid:
            result["dates"]["normalized"].append(normalized)
        else:
            groups = re.findall(r'\d+', token)
            total_digits = sum(len(g) for g in groups)
            if ((len(groups) in (2, 3) and 4 <= total_digits <= 8)):
                result["dates"]["invalid"].append(token)

        is_valid, digits = validate_inn(token)
        if len(digits) in (10, 12):
            if is_valid:
                result["inn"]["valid"].append(digits)
            else:
                result["inn"]["invalid"].append(digits)

    for section in ("phones", "dates", "inn"):
        for key in result[section]:
            result[section][key] = list(set(result[section][key]))

    return result


def generate_comprehensive_report(text) -> dict:
    """
    Run all analysis roles over the same input text and collect results in a single report dictionary.
    Args:
        text (str): Input text to analyze.
    Returns:
        dict: A comprehensive report with results from all analysis functions.
    """

    report = {
        'financial_data': find_and_validate_credit_cards(text),
        'secrets': find_secrets(text),
        'system_info': find_system_info(text),
        'encoded_messages': decode_messages(text),
        'security_threats': analyze_logs(text),
        'normalized_data': normalize_and_validate(text)
    }
    return report


def print_report(report) -> None:
    """
    Print the comprehensive report in a structured format.
    Args:
        report (dict): The comprehensive report dictionary.
    Returns:
        None
    """

    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)

    sections = [
        (ru.FINANCE_DATA, report['financial_data']),
        (ru.SECRET_DATA, report['secrets']),
        (ru.SYSTEM_INFO, report['system_info']),
        (ru.DECODED_MESS, report['encoded_messages']),
        (ru.SAFETY_ALERT, report['security_threats']),
        (ru.NORMALIZED_DATA, report['normalized_data'])
    ]

    for title, data in sections:
        print(f"\n{title}:")
        print("-" * 30)
        if isinstance(data, dict):
            for key, value in data.items():
                print(f"{key}: {value}")
        elif isinstance(data, list):
            for item in data:
                print(item)
        else:
            print(data)


def main() -> None:
    """
    Main function to read input text, generate report, and print it.
    Returns:
        None
    """

    with open('файл плохой.txt', 'r', encoding='utf-8') as f:
        text = f.read()

    report = generate_comprehensive_report(text)
    print_report(report)

    with open("valid_artifacts.txt", "w", encoding="utf-8") as f:
        if "financial_data" in report:
            f.write("cards:\n")
            for card in report["financial_data"].get("valid", []):
                f.write(str(card) + "\n")
        if "secrets" in report:
            f.write("secrets:\n")
            for secret in report["secrets"]:
                f.write(str(secret) + "\n")
        if "system_info" in report:
            f.write("ips:\n")
            for ip in report["system_info"].get("ips", []):
                f.write(str(ip) + "\n")
            f.write("files:\n")
            for file in report["system_info"].get("files", []):
                f.write(str(file) + "\n")
            f.write("emails:\n")
            for email in report["system_info"].get("emails", []):
                f.write(str(email) + "\n")
        if "encoded_messages" in report:
            f.write("base64:\n")
            for item in report["encoded_messages"].get("base64", []):
                f.write(str(item) + "\n")
            f.write("hex:\n")
            for item in report["encoded_messages"].get("hex", []):
                f.write(str(item) + "\n")
            f.write("rot13:\n")
            for item in report["encoded_messages"].get("rot13", []):
                f.write(str(item) + "\n")
        if "security_threats" in report:
            f.write("sql_injections:\n")
            for entry in report["security_threats"].get("sql_injections", []):
                f.write(str(entry) + "\n")
            f.write("xss_attempts:\n")
            for entry in report["security_threats"].get("xss_attempts", []):
                f.write(str(entry) + "\n")
            f.write("suspicious_user_agents:\n")
            for entry in report["security_threats"].get("suspicious_user_agents", []):
                f.write(str(entry) + "\n")
            f.write("failed_logins:\n")
            for entry in report["security_threats"].get("failed_logins", []):
                f.write(str(entry) + "\n")
        if "normalized_data" in report:
            f.write("phones:\n")
            for phone in report["normalized_data"].get("phones", {}).get("valid", []):
                f.write(str(phone) + "\n")
            f.write("inn:\n")
            for inn in report["normalized_data"].get("inn", {}).get("valid", []):
                f.write(str(inn) + "\n")
            f.write("dates:\n")
            for date in report["normalized_data"].get("dates", {}).get("normalized", []):
                f.write(str(date) + "\n")


if __name__ == "__main__":
    main()
