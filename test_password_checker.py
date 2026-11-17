
from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    load_credentials,
    load_breached,
    write_report,
    save_summary,
    load_summary,
    load_history,
    add_to_history,
    save_history
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


# Save and load a summary dictionary.
sample = {
    "total": 2,
    "passed": 1,
    "failed": 1,
    "critical": 1,
    "failed_accounts": ["Gmail"],
    "critical_accounts": ["Gmail"]
}

save_summary(sample, "test_summary.json")
loaded_summary = load_summary("test_summary.json")

assert loaded_summary == sample
print("PASS: save_summary and load_summary returned the same dictionary")


# Check that failed_accounts is a list.
assert isinstance(loaded_summary["failed_accounts"], list)
print("PASS: failed_accounts was loaded as a list")


# Check that no password is saved in the JSON file.
credentials = load_credentials("credentials.txt")

with open("test_summary.json", "r") as f:
    saved_text = f.read()

for credential in credentials:
    assert credential["password"] not in saved_text

print("PASS: No passwords from credentials.txt appear in the JSON file")


#Test load_history when the file does not exist.
history = load_history("missing_history.json")
assert history == []
print("PASS: load_history returned an empty list for a missing file")


#Test adding the first audit run.
history = []
history = add_to_history(history, sample, 3)

assert len(history) == 1
assert history[0]["run"] == 1
assert history[0]["passed"] == sample["passed"]
assert history[0]["failed"] == sample["failed"]
assert history[0]["critical_accounts"] == sample["critical_accounts"]
print("PASS: add_to_history correctly created run 1")


#Test that only the newest runs are kept.
history = []

for i in range(3):
    history = add_to_history(history, sample, 2)

assert [entry["run"] for entry in history] == [2, 3]
print("PASS: add_to_history kept only the newest 2 runs")


#Test saving and loading audit history.
save_history(history, "test_history.json")
loaded_history = load_history("test_history.json")

assert loaded_history == history
print("PASS: save_history and load_history returned the same history")


print("All tests passed.")
