
# Week 06 + Week 07 Password Checker
# ITIA 1510 - Cybersecurity Automation

# Import csv so the program can read the credentials and breach files.
import csv

# The policy dictionary keeps security rules in one place.
# Keeping it outside main allows the tests to import and use it.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}


# Check the password length using the policy settings.
# Reading limits from policy is easier to maintain than hardcoding numbers.
def check_length(password, policy):
    password_length = len(password)

    if password_length < policy["min_length"]:
        return False, "FAIL - Password is too short."

    if password_length >= policy["strong_length"]:
        return True, "PASS - Strong password length."

    return True, "PASS - Password length is acceptable."


# Check whether the password contains at least one number.
def check_digit(password):
    if any(character.isdigit() for character in password):
        return True, "PASS - Password contains a number."

    return False, "FAIL - Password must contain a number."


# Check whether the password contains the username.
def check_username(password, username):
    if username.lower() in password.lower():
        return False, "FAIL - Password contains the username."

    return True, "PASS - Password does not contain the username."


# Check password rotation using the policy settings.
def check_rotation(rotation_interval, policy):
    if rotation_interval > policy["max_rotation_months"]:
        return False, "FAIL - Password rotation is overdue."

    if rotation_interval <= policy["good_rotation_months"]:
        return True, "PASS - Password rotation is good."

    return True, "PASS - Password rotation is acceptable."


# Check whether the password appears in the known breach list.
def check_breach(password, known_breached):
    if password in known_breached:
        return False, "CRITICAL - Password found in breach list."

    return True, "PASS - Password not found in breach list."


# Load credential records from the credentials file.

def load_credentials(filepath):
    credentials = []

    with open(filepath, "r", newline="") as file:
        reader = csv.reader(file)

        for row in reader:
            # Skip empty lines.
            if not row:
                continue

            # Store each row as a dictionary.
            credentials.append({
                "account": row[0],
                "username": row[1],
                "password": row[2],
                "rotation_interval": int(row[3])
            })

    return credentials



# Load known breached passwords from the breach file.
def load_breached(filepath):
    known_breached = []

    with open(filepath, "r") as file:
        for line in file:
            password = line.strip()

            if password:
                known_breached.append(password)

    return known_breached


# Write the audit report to a text file.
def write_report(report_lines, filepath):
    with open(filepath, "w") as file:
        for line in report_lines:
            file.write(line + "\n")


# Audit one password using the security policy.
def audit_password(
    password,
    username,
    rotation_interval,
    known_breached,
    policy,
    report_number,
    total_credentials,
    report_lines
):
    results = []
    critical = False

    # Check password length.
    length_passed, length_message = check_length(password, policy)
    results.append(length_message)

    # Check for a number only when the policy requires it.
    if policy.get("require_digit", False):
        digit_passed, digit_message = check_digit(password)
        results.append(digit_message)
    else:
        digit_passed = True
        results.append("PASS - Number requirement is disabled.")

    # Check whether the password contains the username.
    username_passed, username_message = check_username(password, username)
    results.append(username_message)

    # Check password rotation.
    rotation_passed, rotation_message = check_rotation(
        rotation_interval, policy
    )
    results.append(rotation_message)

    # Check the breach list only when the policy enables it.
    if policy.get("check_breach_list", False):
        breach_passed, breach_message = check_breach(
            password, known_breached
        )
        results.append(breach_message)

        if not breach_passed:
            critical = True
    else:
        breach_passed = True
        results.append("PASS - Breach-list checking is disabled.")

    # Count how many checks passed or failed.
    checks_passed = all([
        length_passed,
        digit_passed,
        username_passed,
        rotation_passed,
        breach_passed
    ])

    if not length_passed or not username_passed:
        critical = True

    # Add the audit results to the report.
    report_lines.append("")
    report_lines.append(
        f"Credential {report_number} of {total_credentials}"
    )
    report_lines.append("Username: " + username)
    report_lines.append("Password audit:")

    for result in results:
        report_lines.append("  " + result)

    if critical:
        report_lines.append("RESULT: CRITICAL")
    elif checks_passed:
        report_lines.append("RESULT: PASS")
    else:
        report_lines.append("RESULT: FAIL")

    return checks_passed, critical


# Main program starts here.
if __name__ == "__main__":

    # Week 07 reads credentials and breached passwords from files.
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")

    total_credentials = len(credentials)

    # The summary dictionary keeps all audit totals together.
    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    report_lines = []

    report_lines.append("PASSWORD SECURITY AUDIT REPORT")
    report_lines.append("=" * 40)
    report_lines.append(
        "NOTE: Credentials and breach list are loaded from files."
    )

    # Process each credential using its dictionary keys.
    for report_number, credential in enumerate(credentials, start=1):

        account = credential["account"]
        username = credential["username"]
        password = credential["password"]
        rotation_interval = credential["rotation_interval"]

        passed, critical = audit_password(
            password,
            username,
            rotation_interval,
            known_breached,
            policy,
            report_number,
            total_credentials,
            report_lines
        )

        summary["total"] += 1

        if passed:
            summary["passed"] += 1
        else:
            summary["failed"] += 1
            summary["failed_accounts"].append(account)

        if critical:
            summary["critical"] += 1
            summary["critical_accounts"].append(account)

    # Print the final audit summary.
    report_lines.append("")
    report_lines.append("=" * 40)
    report_lines.append("AUDIT SUMMARY")
    report_lines.append("=" * 40)
    report_lines.append(f"Credentials audited: {summary.get('total', 0)}")
    report_lines.append(f"Passed: {summary['passed']}")
    report_lines.append(f"Failed: {summary['failed']}")
    report_lines.append(
        "Failed accounts: " + ", ".join(summary["failed_accounts"])
    )
    report_lines.append(f"Critical flags: {summary['critical']}")
    report_lines.append(
        "Critical accounts: " + ", ".join(summary["critical_accounts"])
    )

    # Display the report in the terminal.
    for line in report_lines:
        print(line)

    # Save the same report to report.txt.
    write_report(report_lines, "report.txt")
