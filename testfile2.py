# import requests
# url = 'http://192.168.1.97/base/index.php'
# values = {'username' : 'snort',
#           'password' : '123456'}
#
# r = requests.post(url, data=values)
# # print r.content







import urllib, urllib2, cookielib
#cookie storage
cj = cookielib.CookieJar()
#create an opener
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
#Add useragent, sites don't like to interact programs.
opener.addheaders.append(('User-agent', 'Mozilla/4.0'))
opener.addheaders.append(('Referer', 'http://192.168.1.97/base/index.php'))
login_data = urllib.urlencode({'login' : 'snort', 'password' : '123456', 'submit' : 'submit'})
resp = opener.open('http://192.168.1.97/base/index.php', login_data)
login_data = urllib.urlencode({'submit' : 'Rebuild IP Cache'})
resp2 = opener.open('http://192.168.1.97/base/base_maintenance.php', login_data)
login_data = urllib.urlencode({'submit' : 'Update IP Cache'})
resp2 = opener.open('http://192.168.1.97/base/base_maintenance.php', login_data)
print resp2.read()
resp.close()





# set these to whatever your fb account is
fb_username = "snort"
fb_password = "123456"
fb_submit = "Update IP Cache"


class WebGamePlayer(object):

    def __init__(self, login, password, submit):
        """ Start up... """
        self.login = login
        self.password = password
        self.submit = submit

        self.cj = cookielib.CookieJar()
        self.opener = urllib2.build_opener(
            urllib2.HTTPRedirectHandler(),
            urllib2.HTTPHandler(debuglevel=0),
            urllib2.HTTPSHandler(debuglevel=0),
            urllib2.HTTPCookieProcessor(self.cj)
        )
        self.opener.addheaders = [
            ('User-agent', ('Mozilla/4.0 (compatible; MSIE 6.0; '
                           'Windows NT 5.2; .NET CLR 1.1.4322)'))
        ]

        # need this twice - once to set cookies, once to log in...
        self.loginToFacebook()
        self.loginToFacebook()

    def loginToFacebook(self):
        """
        Handle login. This should populate our cookie jar.
        """
        login_data = urllib.urlencode({
            'login': self.login,
            'password': self.password,
        })
        response = self.opener.open("http://192.168.1.97/base/index.php", login_data)
        return ''.join(response.readlines())

    def ip_cache_update(self):
        login_data = urllib.urlencode({
            'submit': self.submit
        })
        response = self.opener.open("http://192.168.1.97/base/base_maintenance.php", login_data)
        print ''.join(response.readlines())
        return ''.join(response.readlines())

web_login = WebGamePlayer(fb_username, fb_password, fb_submit)
web_login.loginToFacebook()
web_login.ip_cache_update()
