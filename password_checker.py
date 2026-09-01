account = input('account: ')
username = input('username: ')
password = input('password: ')
rotation_interval = int(input('Rotation interval (months): ')) 
password_length = len(password)
length_score = len(password) * 10
rotation_count = 36 // rotation_interval


'''Finding the NIST Password Requirment'''

if password_length < 8:
    lenght_verdict = "WEAK — does not meet minimum length requirements"
elif password_length <= 11:
    lenght_verdict = "MODERATE — meets minimum but falls short of NIST recommendationsmeets minimum but falls short of NIST recommendations"
elif password_length <= 14:
    lenght_verdict = "GOOD — acceptable length for most systems"
else:
    lenght_verdict = "STRONG — meets NIST SP 800-63B recommendations"

has_digit = '0' in password or '1' in password or '2' in password or '3' in password or '4' in password or '5' in password or '6' in password or '7' in password or '8' in password or '9' in password
'''Checking that the password is not the same as the username'''
not_username = password != username
'''checking for rotation frequency '''
if rotation_interval > 12:
    rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
elif rotation_interval >= 6:
    rotation_verdict = "ACCEPTABLE — rotation interval within recommended range"
else:
    rotation_verdict = "EXCELLENT — frequent rotation policy detected"

length_ok = password_length >= 15
overall_pass = length_ok and has_digit and not_username

'''Printing the result'''
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
print('Lenght Verdict:    ', lenght_verdict)
print('Digit Found:       ',has_digit)
print('Username match:    ',not_username)
print('Rotation Verdict:  ',rotation_verdict)
if not_username == False:
    print('CRITICAL — password must not match username.')

print('-----------------------------------------')

if overall_pass:
    print('OVERALL: PASS — password meets all checked criteria')
else:
    print('OVERALL: FAIL — see findings above')

print('========================================')
