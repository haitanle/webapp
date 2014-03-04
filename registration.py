import webapp2
import cgi
import re

form = """

<html>

<form method = "post">
	<b>Signup</b>
	<br>
	<label> Username
		<input type = "text" name= "username" value="%(username)s">
	</label>
	<div style="color:red">%(username_error)s </div> 
	<label> Password
		<input type = "password" name= "password" value="">   <!-- no return input if password do not match -->
	</label>
	<div style="color:red">%(password_error)s </div> 
	<label> Re-enter Password
		<input type = "password" name= "verify" value="">
	</label>
	<div style="color:red">%(password_verify_error)s </div> 
	<label> Email (optional)
		<input type = "text" name= "email" value="%(email)s">
	</label>
	<input type= "submit">
	<div style="color:red">%(email_error)s </div>   <!-- string substition using dictionary -->
	
</form>
</html> 
"""

def escape_html(s):
	return cgi.escape(s,quote=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def validate_username(username):
   return USER_RE.match(username)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def validate_email(email):
	return EMAIL_RE.match(email)

def validate_password(password):
	if password:
		return True
	else:
		return False



class MainPage (webapp2.RequestHandler):
	def get_form(self, username="", username_error="",
						password_error="", password_verify_error="", 
						email="", email_error=""):
		self.response.out.write(form % ({"username":escape_html(username),     # html map : return value
										"username_error":escape_html(username_error),
										"password_error":escape_html(password_error),
										"password_verify_error":escape_html(password_verify_error),
										"email":escape_html(email),
										"email_error":escape_html(email_error) }
										))   
	

	def get(self):
		self.get_form()

	def post(self):
		
		user_username = self.request.get("username")
		user_password = self.request.get("password")
		user_verify_pw = self.request.get("verify")
		user_email = self.request.get("email")

		valid_username = validate_username(user_username)
		valid_password = validate_password(user_password)
		valid_password_matched = user_password == user_verify_pw
		valid_email = validate_email(user_email)

		output = {'username':user_username, 'username_error':"",    #Create hashtable to map error out if needed
					'password_error':"", 
					'password_verify_error':"",
					'email':"", 'email_error':""    }     

		if not valid_username:
			output['username_error'] = 'Invalid username'          #if not valid entry, replaces default

		if not valid_password:
			output['password_error'] = 'Invalid password'

		if not valid_password_matched:
			output['password_verify_error'] = 'Password does not match'

		if user_email:      # use this so that non-email won't get Invalid message 
			if not valid_email:
				output['email'] = user_email
				output['email_error'] = 'Invalid email'
			else:
				output['email'] = user_email   


		if (valid_username and valid_password and valid_password_matched):
			if valid_email or user_email == "":
				self.response.headers.add_header('Set-Cookie', 'user_id=%s' %str(user_username))   #set username in cookie     
				self.redirect('/welcome')  
			

		self.get_form(username=output['username'],    #overriding default parameters if needed 
					   username_error = output['username_error'],
					   password_error = output['password_error'],
					   password_verify_error = output['password_verify_error'],
					   email = output['email'],
					   email_error = output['email_error']   
					 )     


		

class ThanksHandler (webapp2.RequestHandler):
	def get(self):
		user_id = self.request.cookies.get('user_id','Invalid user')  #get the user_id cookie from the browswer 
		self.response.out.write("Welcome "+user_id)
		


app = webapp2.WSGIApplication([
	('/signup', MainPage),
	('/welcome', ThanksHandler),   #URL mapping for the /thanks page
	]
	, debug =True) 










