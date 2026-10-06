def check_length(password):
    # Checks password length against NIST SP 800-63B thresholds.
    # Takes a password string. Returns (length_ok: bool, length_verdict: str).
    password_length = len(password)

    if password_length < 8:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

    length_ok = password_length >= 15
    return length_ok, length_verdict


def check_digit(password):
    # Checks whether a password contains at least one digit.
    # Takes a password string. Returns True if a digit is found, otherwise False.
    has_digit = False

    # Check each character using the loop from Week 03.
    for char in password:
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    # Checks whether the password is different from the username.
    # Takes a password and username string. Returns True if they differ.
    # The password should never be the same as the username.
    not_username = password != username
    return not_username


def check_rotation(rotation_interval):
    # Checks the password rotation interval.
    # Takes the rotation interval in months.
    if rotation_interval > 12:
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= 12
    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    # Checks whether a password appears in the known breached password list.
    # Using "in" checks whether the password exists in the list.
    not_breached = password not in known_breached
    return not_breached


def load_credentials(filepath):
    """Read the credentials file and return a list of dictionaries."""

    credentials = []

    # with automatically closes the file, even if an error happens.
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip blank lines so they are not treated as credentials.
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

            # Skip blank lines in the breach list.
            if line != "":
                known_breached.append(line)

    return known_breached


def write_report(report_lines, filepath):
    """Write each report line to the report file."""

    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


def audit_password(
    account,
    username,
    password,
    rotation_interval,
    known_breached,
    report_number,
    total_credentials,
    report_lines
):
    # Audits one password using all checking functions.
    # Returns passed, failed, and critical counters.

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    not_breached = check_breach(password, known_breached)

    passed = 0
    failed = 0
    critical = 0

    # A username match is a critical security problem.
    if not_username == False:
        critical = 1

    # A breached password is also a critical security problem.
    if not_breached == False:
        critical = 1

    overall_pass = (
        length_ok
        and has_digit
        and not_username
        and not_breached
        and rotation_ok
    )

    if overall_pass:
        passed = 1
    else:
        failed = 1

    # Store the report lines instead of printing them directly.
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

    if not_username == False:
        report_lines.append(
            "CRITICAL:          password must not match username"
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

    # Load credentials from the external credentials file.
    credentials = load_credentials("credentials.txt")

    # Load breached passwords from the external breach file.
    known_breached = load_breached("breached.txt")

    # Store every line that will be printed and written to report.txt.
    report_lines = []

    total_pass = 0
    total_fail = 0
    critical_count = 0

    failed_accounts = []
    critical_accounts = []

    total_credentials = len(credentials)

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
            report_lines
        )

        total_pass += passed
        total_fail += failed
        critical_count += critical

        if failed:
            failed_accounts.append(account)

        if critical:
            critical_accounts.append(account)

    # Add the batch summary after all individual audits.
    report_lines.append("")
    report_lines.append("========================================")
    report_lines.append("     BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append(f"Credentials audited: {total_credentials}")
    report_lines.append(f"Passed:              {total_pass}")
    report_lines.append(f"Failed:              {total_fail}")
    report_lines.append("----------------------------------------")

    if failed_accounts:
        report_lines.append(
            "Failed accounts:     " + ", ".join(failed_accounts)
        )
    else:
        report_lines.append("Failed accounts:     None")

    report_lines.append(f"Critical flags:      {critical_count}")

    if critical_accounts:
        report_lines.append(
            "Critical accounts:   " + ", ".join(critical_accounts)
        )
    else:
        report_lines.append("Critical accounts:   None")

    report_lines.append("========================================")

    # Print the same lines that will be saved to report.txt.
    for line in report_lines:
        print(line)

    # Write the complete report to report.txt.
    write_report(report_lines, "report.txt")