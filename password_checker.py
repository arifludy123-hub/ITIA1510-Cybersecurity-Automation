def check_length(password):
    # Checks password length against NIST SP 800-63B thresholds.
    # Takes a password string. Returns (length_ok: bool, length_verdict: str).
    # 
    password_length = len(password)

    if password_length < 8:
        length_verdict = "WEAK — does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_verdict = "GOOD — acceptable length for most systems"
    else:
        length_verdict = "STRONG — meets NIST SP 800-63B recommendations"

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
    # Takes a password and username string. Returns True if they differ, otherwise False.
    
    # The password should never be the same as the username.
    not_username = password != username

    return not_username


def check_rotation(rotation_interval):
    # Checks the password rotation interval.
    # Takes the rotation interval in months. Returns (rotation_ok: bool, rotation_verdict: str).
    
    if rotation_interval > 12:
        rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE — rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT — frequent rotation policy detected"

    rotation_ok = rotation_interval <= 12

    return rotation_ok, rotation_verdict


def audit_password(account, username, password, rotation_interval):
    # Audits one password using the four checking functions.
    # Takes account, username, password, and rotation interval.
    # Returns (passed, failed, critical) counters as 1 or 0.
    
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)

    overall_pass = length_ok and has_digit and not_username

    passed = 0
    failed = 0
    critical = 0

    # Print the password audit report.
    print('=========================================')
    print('        PASSWORD AUDIT REPORT')
    print("=========================================")
    print('Account:           ', account)
    print('Username:          ', username)
    print('Password length:   ', password_length, 'characters')
    print('Length score:      ', length_score, 'points')
    print('Rotation interval: ', rotation_interval, 'months')
    print('Rotations (3 yr):  ', rotation_count)
    print('-----------------------------------------')
    print('Lenght Verdict:    ', length_verdict)
    print('Digit Found:       ', has_digit)
    print('Username match:    ', not_username)
    print('Rotation Verdict:  ', rotation_verdict)

    if not_username == False:
        print('CRITICAL — password must not match username.')
        critical = 1

    print('-----------------------------------------')

    if overall_pass:
        print('OVERALL: PASS — password meets all checked criteria')
        passed = 1
    else:
        print('OVERALL: FAIL — see findings above')
        failed = 1

    return passed, failed, critical


if __name__ == '__main__':
    # This block prevents the input loop from running when tests import this file.
    batch_size = 3
    count = 0

    # Results of all passwords processed in the batch.
    total_pass = 0
    total_fail = 0
    critical_count = 0

    while count < batch_size:

        # Get information for one password.
        account = input('account: ')
        username = input('username: ')
        password = input('password: ')
        rotation_interval = int(input('Rotation interval (months): '))

        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval
        )

        total_pass += passed
        total_fail += failed
        critical_count += critical

        count += 1

    print('========================================')
    print('=========================================')
    print('Total passwords audited: ', count)
    print('Total passed:             ', total_pass)
    print('Total failed:             ', total_fail)
    print('CRITICAL username flags:  ', critical_count)
    print('=========================================')
    print('NOTE: Input is still hardcoded -- file reading coming in Week 08.')