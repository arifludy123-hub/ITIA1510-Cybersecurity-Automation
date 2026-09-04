
batch_size = 3
count = 0

# the results of all passwords processed in the batch.
total_pass = 0
total_fail = 0
critical_count = 0
while count < batch_size:

    #inputs
    account = input('account: ')
    username = input('username: ')
    password = input('password: ')
    rotation_interval = int(input('Rotation interval (months): ')) 
    password_length = len(password)
    length_score = len(password) * 10
    rotation_count = 36 // rotation_interval
    


#Finding the NIST Password Requirment

    if password_length < 8:
        length_verdict = "WEAK — does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE — meets minimum but falls short of NIST recommendationsmeets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_verdict = "GOOD — acceptable length for most systems"
    else:
        length_verdict = "STRONG — meets NIST SP 800-63B recommendations"

    has_digit = False
    for char in password:
            if char in '0123456789':
                has_digit = True

# Checking that the password is not the same as the username
    not_username = password != username
    # checking for rotation frequency
    if rotation_interval > 12:
        rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE — rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT — frequent rotation policy detected"

    length_ok = password_length >= 15
    overall_pass = length_ok and has_digit and not_username

    #Printing the result
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
    print('Digit Found:       ',has_digit)
    print('Username match:    ',not_username)
    print('Rotation Verdict:  ',rotation_verdict)
    if not_username == False:
        print('CRITICAL — password must not match username.')
        critical_count += 1

    print('-----------------------------------------')

    if overall_pass:
        print('OVERALL: PASS — password meets all checked criteria')
        total_pass += 1
    else:
        print('OVERALL: FAIL — see findings above')
        total_fail += 1
    count +=1

print('========================================')
print('=========================================')
print('Total passwords audited: ', count)
print('Total passed:             ', total_pass)
print('Total failed:             ', total_fail)
print('CRITICAL username flags:  ', critical_count)
print('=========================================')
print('NOTE: Input is still hardcoded -- file reading coming in Week 08.')  
