account = input('account: ')
username = input('username: ')
password = input('password: ')
rotation_interval = int(input('Rotation interval (months): ')) 
password_length = len(password)
length_score = len(password) * 10
rotation_count = 36 // rotation_interval


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
print('NOTE: Classification requires conditionals -- coming in Week 02.')
print('========================================')
