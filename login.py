import webapp2
import cgi
import re

form = """

<html>

<form method = "post">
	<b>Login</b>
	<br>
	<label> Username
		<input type = "text" name= "username" value="%(username)s">
	</label>
	<div style="color:red">%(username_error)s </div> 
	<label> Password
		<input type = "password" name= "password" value="">   <!-- no return input if password do not match -->
	</label>
	<div style="color:red">%(password_error)s </div> 
	<input type= "submit">
</form> 
</html> 
"""


#Hash and Salt Functions for password storage

import random
import string
import hashlib

def make_salt():
    return ''.join(random.choice(string.letters) for x in range(5))   

def make_pw_hash(name, pw, salt = None):
    if salt is None:
        salt = make_salt()   #Make Salt only if there is no Salt 
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(",", 1)[1]
    return make_pw_hash(name, pw, salt) == h


#Implement the hash_str function to use HMAC and our SECRET for Cookie checking
import hmac

SECRET = 'secret'

def hash_str(s):
    return hmac.new (SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val




def escape_html(s):
	return cgi.escape(s,quote=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def validate_username(username):
   return USER_RE.match(username)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def validate_email(email):
	return EMAIL_RE.match(email)

def validate_password(password):  #check if a password is entered 
	if password:
		return True
	else:
		return False

#USER DATABASE
from google.appengine.ext import db

class User (db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

#Check if username exist and get the ID
def username_exist(username):
	q = db.GqlQuery("Select * from User")
	for user in q:
		if username == user.username:
			userID = str(user.key().id())
			return True, userID  
	return False, None


class MainPage(webapp2.RequestHandler):
	def get_form(self, username="", username_error="",
						password_error=""):
		self.response.out.write(form % ({"username":escape_html(username),     # html map : return value
										"username_error":escape_html(username_error),
										"password_error":escape_html(password_error)
										}))

	def get(self):
		self.get_form()

	def post(self):
		
		user_username = self.request.get("username")
		user_password = self.request.get("password")

		valid_username = validate_username(user_username)
		valid_password = False  #only check password if username is valid and unique
		if valid_username:
			user_exist, userID = username_exist(user_username) #if username exist, get True and userID

			if userID:
				pwHash = User.get_by_id(int(userID)).password
				valid_password = valid_pw(user_username, user_password, pwHash)

		output = {'username':user_username, 'username_error':"",    #Create hashtable to map error out if needed
					'password_error':""}     

		if not valid_username:  
			output['username_error'] = 'Invalid username'         
		else:
			if not user_exist:   #check for invalid username first, only 1 error message is produced
				output['username_error'] = 'No such user'
			else:
				if not valid_password:
					output['password_error'] = 'Incorrect password'


		if (valid_username and user_exist and valid_password):

				hashID = make_secure_val(userID) #hash the ID 
				self.response.headers.add_header('Set-Cookie', 'user_id=%s ; path = / ' %hashID)   #set ID in cookie     
				self.redirect('/welcome')  
			

		self.get_form(username=output['username'],    #overriding default parameters if needed 
					   username_error = output['username_error'],
					   password_error = output['password_error'],   
					 )     

class ThanksHandler (webapp2.RequestHandler):

	def get(self):
		hashID = self.request.cookies.get('user_id', None)  #get the user_id cookie from the browswer 
		if hashID:
			userID = check_secure_val(hashID) #return ID if valid 
			if userID:
				username = User.get_by_id(int(userID)).username   #get username from ID 
				self.response.out.write("Welcome "+username)
			else:
				self.redirect('/login')
		else:
			self.redirect('/login')


app = webapp2.WSGIApplication([
	('/login', MainPage),
	('/welcome', ThanksHandler),   #URL mapping for the /thanks page
	]
	, debug =True)





