from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    load_credentials,
    load_breached,
    write_report
)


# Load the breach list from the external file.
known_breached = load_breached("breached.txt")


# Test check_length with a weak password.
length_ok, length_verdict = check_length("MccS")
assert length_ok == False
print("PASS: check_length correctly identified weak password (length_ok = False)")


# Test check_length with a strong password.
length_ok, length_verdict = check_length("SouthCampusMACOMB")
assert length_ok == True
print("PASS: check_length correctly identified strong password (length_ok = True)")


# Test check_digit with no digits.
assert check_digit("ArifulHasan") == False
print("PASS: check_digit correctly returned False for password with no digits")


# Test check_digit with a digit.
assert check_digit("Room259SouthC") == True
print("PASS: check_digit correctly returned True for password containing a digit")


# Test when password matches username.
assert check_username("CyberSecurity", "CyberSecurity") == False
print("PASS: check_username correctly returned False when password matches username")


# Test when password differs from username.
assert check_username("Automation", "Automation2026") == True
print("PASS: check_username correctly returned True when password differs from username")


# Test check_breach with a password that is in the breach list.
assert check_breach("password123", known_breached) == False
print("PASS: check_breach correctly returned False for breached password")


# Test check_breach with a password that is not in the breach list.
assert check_breach("Blue-Harbor-72-Lantern", known_breached) == True
print("PASS: check_breach correctly returned True for password not in breach list")


# Test rotation interval above 12 months.
rotation_ok, rotation_verdict = check_rotation(14)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for 14-month interval")


# Test rotation interval within 12 months.
rotation_ok, rotation_verdict = check_rotation(6)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for 6-month interval")


# Test load_credentials returns a list.
credentials = load_credentials("credentials.txt")
assert isinstance(credentials, list)
print("PASS: load_credentials correctly returned a list")


# Test the first credential contains an account key.
assert "account" in credentials[0]
print("PASS: first credential correctly contains an account key")


# Test load_breached returns a list.
breached = load_breached("breached.txt")
assert isinstance(breached, list)
print("PASS: load_breached correctly returned a list")


# Test password123 is in the breach list.
assert "password123" in breached
print("PASS: load_breached correctly loaded password123")


# Test write_report writes the lines correctly.
test_lines = ["first line", "second line"]
write_report(test_lines, "test_report.txt")

with open("test_report.txt", "r") as f:
    report_text = f.read()

assert report_text == "first line\nsecond line\n"
print("PASS: write_report correctly wrote the report")


print("----------------------------------------")
print("All 15 tests passed.")