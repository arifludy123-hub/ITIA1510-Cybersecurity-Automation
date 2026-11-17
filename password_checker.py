
import json


# Week 06: Keep policy settings outside the main program.
# This makes it easier to update security requirements in one place.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}


def check_length(password, policy=policy):
    # Checks password length using the policy settings.
    password_length = len(password)

    if password_length < policy["min_length"]:
        length_verdict = "WEAK -- password is too short"
    elif password_length <= policy["min_length"] + 3:
        length_verdict = "MODERATE -- password length is acceptable"
    elif password_length < policy["strong_length"]:
        length_verdict = "GOOD -- password length is good"
    else:
        length_verdict = "STRONG -- password length is excellent"

    length_ok = password_length >= policy["strong_length"]

    return length_ok, length_verdict


def check_digit(password):
    # Checks whether a password contains at least one digit.
    has_digit = False

    for char in password:
        if char in "0123456789":
            has_digit = True

    return has_digit


def check_username(password, username):
    # Checks whether the password is different from the username.
    not_username = password != username

    return not_username

def check_rotation(rotation_interval, policy=policy):
    # Uses policy settings instead of hardcoded rotation limits.
    if rotation_interval > policy["max_rotation_months"]:
        rotation_verdict = (
            "WARNING -- rotation interval exceeds recommended maximum of 12 months"
        )
    elif rotation_interval >= policy["good_rotation_months"]:
        rotation_verdict = (
            "ACCEPTABLE -- rotation interval within recommended range"
        )
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= policy["max_rotation_months"]

    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    # Checks whether the password appears in the known breached password list.
    not_breached = password not in known_breached

    return not_breached


def load_credentials(filepath):
    """Read the credentials file and return a list of dictionaries."""

    credentials = []

    # Read each line and skip blank lines.
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            if line == "":
                continue

            fields = line.split(",")

            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3])
            })

    return credentials


def load_breached(filepath):
    """Read the breached password file and return a list of passwords."""

    known_breached = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            if line != "":
                known_breached.append(line)

    return known_breached


def write_report(report_lines, filepath):
    """Write each report line to the report file."""

    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


def save_summary(summary, filepath):
    # Week 09: Save the audit summary as JSON.
    # Passwords are not included in the summary dictionary.
    with open(filepath, "w") as f:
        json.dump(summary, f, indent=2)


def load_summary(filepath):
    # Week 09: Load the saved JSON summary.
    with open(filepath, "r") as f:
        return json.load(f)


def audit_password(
    account,
    username,
    password,
    rotation_interval,
    known_breached,
    report_number,
    total_credentials,
    report_lines,
    policy
):
    # Audits one password using all checking functions.
    # Returns passed, failed, and critical counters.

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Check password length.
    length_ok, length_verdict = check_length(password, policy)

    # Check whether the password contains a digit.
    has_digit = check_digit(password)

    if has_digit:
        digit_verdict = "PASS -- password contains a digit"
    else:
        digit_verdict = "FAIL -- password does not contain a digit"

    # Check whether the password matches the username.
    not_username = check_username(password, username)

    if not_username:
        username_verdict = "PASS -- password is different from username"
    else:
        username_verdict = "FAIL -- password matches username"

    # Check password rotation interval.
    rotation_ok, rotation_verdict = check_rotation(
        rotation_interval, policy
    )

    # Check whether the password appears in the breach list.
    if policy["check_breach_list"]:
        not_breached = check_breach(password, known_breached)
    else:
        not_breached = True

    passed = 0
    failed = 0
    critical = 0

    # A username match is a critical security problem.
    if not not_username:
        critical = 1

    # A breached password is also a critical security problem.
    if not not_breached:
        critical = 1

    overall_pass = (
        length_ok
        and (has_digit or not policy["require_digit"])
        and not_username
        and not_breached
        and rotation_ok
    )

    if overall_pass:
        passed = 1
    else:
        failed = 1

    # Store report lines so they can be printed and saved.
    report_lines.append("========================================")
    report_lines.append(
        f"   PASSWORD AUDIT REPORT  ({report_number} of {total_credentials})"
    )
    report_lines.append("========================================")
    report_lines.append(f"Account:           {account}")
    report_lines.append(f"Username:          {username}")
    report_lines.append(f"Password length:   {password_length} characters")
    report_lines.append(f"Length score:      {length_score} points")
    report_lines.append(f"Rotation interval: {rotation_interval} months")
    report_lines.append(f"Rotations (3 yr):  {rotation_count}")
    report_lines.append("----------------------------------------")
    report_lines.append(f"Length verdict:    {length_verdict}")
    report_lines.append(f"Digit verdict:     {digit_verdict}")
    report_lines.append(f"Username verdict:  {username_verdict}")

    if has_digit:
        report_lines.append("Digit found:       YES")
    else:
        report_lines.append("Digit found:       NO")

    if not_username:
        report_lines.append("Username match:    NO")
    else:
        report_lines.append("Username match:    YES")

    if not_breached:
        report_lines.append(
            "Breach check:      PASS -- password not found in known breach list"
        )
    else:
        report_lines.append(
            "Breach check:      CRITICAL -- password found in known breach list"
        )

    report_lines.append(f"Rotation verdict:  {rotation_verdict}")

    if not not_username:
        report_lines.append(
            "CRITICAL:          password must not match username"
        )

    if not not_breached:
        report_lines.append(
            "CRITICAL:          password appears in known breach list"
        )

    report_lines.append("----------------------------------------")

    if overall_pass:
        report_lines.append(
            "OVERALL: PASS -- password meets all checked criteria"
        )
    else:
        report_lines.append(
            "OVERALL: FAIL -- see findings above"
        )

    report_lines.append("========================================")

    return passed, failed, critical


if __name__ == "__main__":

    # Load credentials and breached passwords from external files.
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")

    report_lines = []

    # Week 06: Use one summary dictionary instead of separate counters.
    summary = {
        "total": len(credentials),
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    # .get() safely reads the total, using zero if the key is missing.
    total_credentials = summary.get("total", 0)

    for report_number, credential in enumerate(credentials, start=1):

        account = credential["account"]
        username = credential["username"]
        password = credential["password"]
        rotation_interval = credential["rotation_interval"]

        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval,
            known_breached,
            report_number,
            total_credentials,
            report_lines,
            policy
        )

        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed:
            summary["failed_accounts"].append(account)

        if critical:
            summary["critical_accounts"].append(account)

    # Add the batch summary after all individual audits.
    report_lines.append("")
    report_lines.append("========================================")
    report_lines.append("        BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append(f"Credentials audited: {summary['total']}")
    report_lines.append(f"Passed:               {summary['passed']}")
    report_lines.append(f"Failed:               {summary['failed']}")
    report_lines.append("----------------------------------------")

    if summary["failed_accounts"]:
        report_lines.append(
            "Failed accounts:     " + ", ".join(summary["failed_accounts"])
        )
    else:
        report_lines.append("Failed accounts:     None")

    report_lines.append(f"Critical flags:      {summary['critical']}")

    if summary["critical_accounts"]:
        report_lines.append(
            "Critical accounts:   " + ", ".join(summary["critical_accounts"])
        )
    else:
        report_lines.append("Critical accounts:   None")

    report_lines.append("========================================")

    # Print and save the report.
    for line in report_lines:
        print(line)

    write_report(report_lines, "report.txt")

    # Week 09: Save the summary after completing the audit.
    save_summary(summary, "audit_summary.json")
