
# ITIA 1510 - Cybersecurity Automation

import json
import os


# The policy dictionary keeps security rules in one place.
# Keeping it outside main allows the tests to import and use it.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True,
    "history_runs": 3
}


def check_length(password, policy=policy):
    # Check password length using the policy settings.
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
    # Check whether a password contains at least one digit.
    for char in password:
        if char in "0123456789":
            return True

    return False


def check_username(password, username):
    # Check whether the password is different from the username.
    return password != username


def check_rotation(rotation_interval, policy=policy):
    # Check password rotation using policy settings.
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
    # Check whether the password appears in the known breached password list.
    return password not in known_breached


def load_credentials(filepath):
    # Read credentials and convert each row into a dictionary.
    credentials = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            if not line:
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
    # Read the known breached passwords from the external file.
    known_breached = []

    with open(filepath, "r") as f:
        for line in f:
            password = line.strip()

            if password:
                known_breached.append(password)

    return known_breached


def write_report(report_lines, filepath):
    # Write the audit report to a text file.
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


def save_summary(summary, filepath):
    # Save the batch summary as JSON for another program to read.
    # The summary contains counts and account names, not passwords.
    with open(filepath, "w") as f:
        json.dump(summary, f, indent=2)


def load_summary(filepath):
    # Load the JSON summary and return it as a dictionary.
    with open(filepath, "r") as f:
        summary = json.load(f)

    return summary


def load_history(filepath):
    # Return an empty list when the history file does not exist yet.
    # This allows the program to run normally for the first time.
    if not os.path.exists(filepath):
        return []

    with open(filepath, "r") as f:
        history = json.load(f)

    return history


def add_to_history(history, summary, keep):
    # Get the next run number from the newest entry.
    # The history length cannot be used because old entries are trimmed.
    if history:
        next_run = history[-1]["run"] + 1
    else:
        next_run = 1

    new_entry = {
        "run": next_run,
        "passed": summary["passed"],
        "failed": summary["failed"],
        "critical_accounts": summary["critical_accounts"]
    }

    history.append(new_entry)

    # Keep only the newest number of runs allowed by the policy.
    history = history[-keep:]

    return history


def save_history(history, filepath):
    # Save the audit history as formatted JSON.
    with open(filepath, "w") as f:
        json.dump(history, f, indent=2)


def breach_verdicts(username, credentials, known_breached):
    # Only include accounts belonging to the requested username.
    accounts = []

    for credential in credentials:
        if credential["username"] == username:

            # check_breach() returns True when a password is NOT breached.
            # Therefore, on_breach_list must be the opposite result.
            on_breach_list = not check_breach(
                credential["password"],
                known_breached
            )

            # Leave out passwords to protect sensitive information.
            accounts.append({
                "account": credential["account"],
                "on_breach_list": on_breach_list
            })

    return {
        "username": username,
        "accounts": accounts
    }


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
    # Audit one password using all configured security checks.
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Check password length.
    length_ok, length_verdict = check_length(password, policy)

    # Check whether the password contains a digit.
    has_digit = check_digit(password)

    if has_digit or not policy["require_digit"]:
        digit_verdict = "PASS -- password contains a digit"
    else:
        digit_verdict = "FAIL -- password does not contain a digit"

    # Check whether the password matches the username.
    not_username = check_username(password, username)

    if not_username:
        username_verdict = "PASS -- password is different from username"
    else:
        username_verdict = "FAIL -- password matches username"

    # Check password rotation.
    rotation_ok, rotation_verdict = check_rotation(
        rotation_interval, policy
    )

    # Check whether the password appears in the breach list.
    if policy["check_breach_list"]:
        not_breached = check_breach(password, known_breached)
    else:
        not_breached = True

    # Determine which security problems are critical.
    critical = 0

    if not not_username or not not_breached:
        critical = 1

    overall_pass = (
        length_ok
        and (has_digit or not policy["require_digit"])
        and not_username
        and not_breached
        and rotation_ok
    )

    passed = 1 if overall_pass else 0
    failed = 0 if overall_pass else 1

    # Add individual audit results to the report.
    report_lines.append("========================================")
    report_lines.append(
        f"PASSWORD AUDIT REPORT ({report_number} of {total_credentials})"
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

    # Keep all batch audit counts and account names in one dictionary.
    summary = {
        "total": len(credentials),
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    total_credentials = summary.get("total", 0)

    # Audit each credential and update the batch summary.
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

    # Save the batch summary after writing the text report.
    save_summary(summary, "audit_summary.json")

    # Load previous audit runs and add the current run.
    history = load_history("audit_history.json")

    history = add_to_history(
        history,
        summary,
        policy["history_runs"]
    )

    # Save the updated history for future audit runs.
    save_history(history, "audit_history.json")

    # Week 11: Generate breach verdicts for jsmith.
    verdicts = breach_verdicts("jsmith", credentials, known_breached)

    # Print the verdicts in readable JSON format.
    print(json.dumps(verdicts, indent=2))

    # Save the verdicts without exposing any passwords.
    with open("breach_check.json", "w") as f:
        json.dump(verdicts, f, indent=2)
