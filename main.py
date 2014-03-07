import jinja2   #had to add Jinja2 under libraries in app.yaml
import os     #this module lets us get the path to our 'templates' folder 
import webapp2
import re

SECRET = 'mySecretKey'


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#Handle Hashing 
import hmac

#get the Hash output from the value using hmac
def hash_str(s): 
    return hmac.new(SECRET, s).hexdigest()

#Return the value and Hash ouptut, used to Set-Cookie 
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

#get value from cookie 'value | hashoutput'
def check_secure_val(h):
    value = h.rsplit('|', 1)[0]  #split by the first pip | (max 1), starting from the right side
    if h == make_secure_val(value):
        return value	

class Handler(webapp2.RequestHandler):

	def write(self, *a , **kwargs):
		self.response.out.write(*a, **kwargs)  #write out template website with Template environment

	def render_str(self, template, **kwargs):
		template = env.get_template(template)   #load template environment
		return template.render(**kwargs)  # render/make the template website with input variables
 
	def render(self, template, **kwargs):
		self.write(self.render_str(template, **kwargs))  

	
class Signup(Handler):

	# def render_front(self, template, username="", username_error = "", password_error= "", 
	# 								password_verify_error = "", email = "", email_error = ""):

	# 	if template == "front.html":
	# 		blogs = db.GqlQuery("Select * From Blog Order By created DESC LIMIT 10")

	# 	self.render(template, subject = subject, 
	# 							  content = content, 
	# 							  error = error, 
	# 							  blogs = blogs)

	def get(self):
		self.render("registration.html")


app = webapp2.WSGIApplication([
	('/signup', Signup),
	#('/login', Login), 
	#('/welcome', Welcome)
	]
	, debug =True)




