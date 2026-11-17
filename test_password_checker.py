
# ITIA 1510 - Cybersecurity Automation

import json
import os
import password_checker

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
    save_history,
    breach_verdicts,
    length_verdicts,
    rotation_verdicts,
    CHECK_NAMES,
    run_check,
    log_check,
    read_audit_log
)


# Load the breach list from the external file.
known_breached = load_breached("breached.txt")

# Send all test run_check() calls to a separate test log.
# This prevents the tests from changing the real audit_log.jsonl.
password_checker.AUDIT_LOG = "test_audit_log.jsonl"


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


# Test load_history when the file does not exist.
history = load_history("missing_history.json")
assert history == []
print("PASS: load_history returned an empty list for a missing file")


# Test adding the first audit run.
history = []
history = add_to_history(history, sample, 3)

assert len(history) == 1
assert history[0]["run"] == 1
assert history[0]["passed"] == sample["passed"]
assert history[0]["failed"] == sample["failed"]
assert history[0]["critical_accounts"] == sample["critical_accounts"]
print("PASS: add_to_history correctly created run 1")


# Test that only the newest runs are kept.
history = []

for i in range(3):
    history = add_to_history(history, sample, 2)

assert [entry["run"] for entry in history] == [2, 3]
print("PASS: add_to_history kept only the newest 2 runs")


# Test saving and loading audit history.
save_history(history, "test_history.json")
loaded_history = load_history("test_history.json")

assert loaded_history == history
print("PASS: save_history and load_history returned the same history")


# Test breach_verdicts for jsmith.
credentials = load_credentials("credentials.txt")

result = breach_verdicts("jsmith", credentials, known_breached)

assert result["username"] == "jsmith"
assert result["accounts"][0] == {
    "account": "Gmail",
    "on_breach_list": True
}

print("PASS: breach_verdicts marked the Gmail password as on the breach list")


# Test a username with no accounts.
result = breach_verdicts("nobody", credentials, known_breached)

assert result["username"] == "nobody"
assert result["accounts"] == []

print("PASS: breach_verdicts returned an empty accounts list for nobody")


# Test that no passwords appear in the verdict result.
result = breach_verdicts("jsmith", credentials, known_breached)
verdict_text = json.dumps(result)

for credential in credentials:
    if credential["username"] == "jsmith":
        if credential["password"] != credential["username"]:
            assert credential["password"] not in verdict_text

print("PASS: breach_verdicts did not include any passwords")


# Test length_verdicts for jsmith.
result = length_verdicts("jsmith", credentials, known_breached)

assert result["username"] == "jsmith"
assert result["accounts"][2] == {
    "account": "VPN",
    "long_enough": True
}

print("PASS: length_verdicts correctly identified the VPN password as long enough")


# Test rotation_verdicts for the SSH Server account.
result = rotation_verdicts("jsmith", credentials, known_breached)

assert result["username"] == "jsmith"
assert result["accounts"][1] == {
    "account": "SSH Server",
    "rotation_months": 24,
    "rotation_ok": False
}

print("PASS: rotation_verdicts correctly identified the SSH Server rotation interval")


# Test CHECK_NAMES contains the three supported checks in the correct order.
assert CHECK_NAMES == [
    "check_breach",
    "check_length",
    "check_rotation"
]

print("PASS: CHECK_NAMES contains all three check names in the correct order")


# Test run_check returns the same result as breach_verdicts.
direct_result = breach_verdicts("jsmith", credentials, known_breached)

run_result = run_check(
    "check_breach",
    "jsmith",
    credentials,
    known_breached
)

assert run_result == direct_result

print("PASS: run_check correctly selected breach_verdicts")


# Test run_check refuses an unknown check name.
result = run_check(
    "reset_password",
    "jsmith",
    credentials,
    known_breached
)

assert result == {"error": "unknown check"}

print("PASS: run_check refused a name that is not one of its checks")


# Week 13: Remove the previous test log before starting new log tests.
if os.path.exists("test_audit_log.jsonl"):
    os.remove("test_audit_log.jsonl")


# Test that log_check writes exactly the required keys.
sample_result = {"status": "test passed"}

log_check(
    "check_length",
    "jsmith",
    sample_result,
    "test_audit_log.jsonl"
)

entries = read_audit_log("test_audit_log.jsonl")

assert len(entries) == 1
assert set(entries[0].keys()) == {
    "check",
    "result",
    "time",
    "username"
}
assert entries[0]["check"] == "check_length"
assert entries[0]["username"] == "jsmith"
assert entries[0]["result"] == sample_result

print("PASS: log_check wrote an entry with exactly the required keys")


# Test that run_check logs successful and refused checks in order.
run_check(
    "check_length",
    "jsmith",
    credentials,
    known_breached
)

run_check(
    "reset_password",
    "jsmith",
    credentials,
    known_breached
)

entries = read_audit_log("test_audit_log.jsonl")

assert entries[-2]["check"] == "check_length"
assert entries[-1]["check"] == "reset_password"
assert entries[-1]["result"] == {"error": "unknown check"}

print("PASS: run_check logged both supported and refused checks in order")


# Test that the audit log does not expose credential passwords.
with open("test_audit_log.jsonl", "r") as f:
    audit_text = f.read()

for credential in credentials:
    if credential["password"] != credential["username"]:
        assert credential["password"] not in audit_text

print("PASS: No credential passwords appear in the audit log")


print("All tests passed.")
