import jinja2   #had to add Jinja2 under libraries in app.yaml
import os     #this module lets us get the path to our 'templates' folder 
import webapp2
import re

SECRET = 'mySecretKey'   #used to Hash cookie 

#USER DATABASE
from google.appengine.ext import db

class User (db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_name(cls, name):  #class method to get the entity by the name, do this instead of GQl query
		return cls.all().filter('username =', name).get()

	@classmethod   #create User object
	def register(cls,username, password, email = ""):
		pw_hash = make_pw_hash(username, password)   #Hash and Salt password
		user = User(username = username, password = pw_hash, email = email) #create username, password, email entry 
		return user

	@classmethod
	def login(cls,username, pw):   #check if user and pw is valid from Login page
		u = cls.by_name(username)
		if u and valid_pw(username, pw, u.password):
			return u 

class Blog (db.Model):

	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	user = db.StringProperty()
	coors = db.GeoPtProperty()

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


#Handle Hashing for 'cookie'
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

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def validate_username(username):
   return USER_RE.match(username)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def validate_email(email):
	return not email or EMAIL_RE.match(email)   #check if only email is present 

def validate_password(password):
	if password:
		return True
	else:
		return False

#Check if username is unique
def unique_username(username):
	q = db.GqlQuery("Select * from User")
	for user in q:
		if username == user.username:
			return False 
	return True 

#Check if username exist and get the ID
def username_exist(username):
	q = db.GqlQuery("Select * from User")
	for user in q:
		if username == user.username:
			userID = str(user.key().id())
			return True, userID  
	return False, None


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class Handler(webapp2.RequestHandler):

	def write(self, *a , **kwargs):
		self.response.out.write(*a, **kwargs)  #write out template website with Template environment

	def render_str(self, template, **kwargs):
		template = env.get_template(template)   #load template environment
		return template.render(**kwargs)  # render/make the template website with input variables
 
	def render(self, template, **kwargs):
		self.write(self.render_str(template, **kwargs))

	def set_secure_cookie(self, name, val):
		val = make_secure_val(val) #hash the value
		self.response.headers.add_header('Set-Cookie', '%s=%s ; path = / ' %(name, val))   #set cookie in header

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name, None)  #get the 'name' cookie from the browswer 
		return cookie_val and check_secure_val(cookie_val) #return value if hashID exist
	
	def initialize(self, *a, **kw): #override's GAE initialize to also check for userID
		webapp2.RequestHandler.initialize(self, *a, **kw)  #create Handler object for request, response
		uid = self.read_secure_cookie('user_id') #get user's ID from cookie
		self.user = uid and User.get_by_id(int(uid)) #set ID to self.user

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))  #log the user by setting cookie to ID

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id =; path = /')

from xml.dom import minidom

def get_coords(xml):
    d = minidom.parseString(xml)
    coords = d.getElementsByTagName("gml:coordinates")
    if coords and coords[0].childNodes[0].nodeValue:
    	lon, lat = coords[0].childNodes[0].nodeValue.split(',')
        # return lat, lon
        return db.GeoPt(lat,lon)  #DataStore Coordinates type

import urllib2 

IP_URL = 'http://api.hostip.info/?ip='
def getCoors(ip):
	ip = "4.2.2.2"   #test ip
	ip = "174.121.194.34"
	url = IP_URL + ip 
	content = None 
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return 

	if content: 
		return get_coords(content)


GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
    markers = ''
    markers = '&'.join('markers=%s,%s' %(p.lat, p.lon) for p in points)
    return GMAPS_URL + markers




class Signup(Handler):  #form and input checking for registration page

	def get(self):
		self.render("registration.html")

	def post(self):
		have_error = False
		self.user_username = self.request.get("username")
		self.user_password = self.request.get("password")
		self.user_verify_pw = self.request.get("verify")
		self.user_email = self.request.get("email")

		param = dict(username = self.user_username,   #Dictionary constructor
						email = self.user_email)

		if not validate_username(self.user_username):
			param['username_error'] = 'Invalid username'
			have_error = True 

		if not validate_password(self.user_password):
		 	param['password_error'] = 'Invalid password'
			have_error = True 
		elif self.user_password != self.user_verify_pw:
			param['password_verify_error'] = "Your passwords didn't match."
			have_error = True
	
		if not validate_email(self.user_email):
			param['email_error'] = 'Invalid email'
			have_error = True


		if have_error:
			self.render("registration.html", **param)
		else:
			self.done()
			

		def done(self, *a, **kw):   #won't be used, registration implements its own 'done' method
			raise NotImplementedError 

class Registration(Signup):  #uses 'get' and 'post' method of Signup
	
	def done(self):
		u = User.by_name(self.user_username)
		if u:
			msg = 'That user already exist'
			self.render("registration.html", username_error = msg)
		else:
			newUser = User.register(self.user_username,    #register user with class method 
					           self.user_password, self.user_email)
			newUser.put()
			self.login(newUser) 
			self.redirect('/blog')

class Login(Handler):
	
	def get(self):
		self.render("login.html")

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

		params = dict(username = user_username)

		if not valid_username:  
			params['username_error'] = 'Invalid username'         
		else:
			if not user_exist:   #check for invalid username first, only 1 error message is produced
				params['username_error'] = 'No such user'
			else:
				if not valid_password:
					params['password_error'] = 'Incorrect password'

		u = User.login(user_username, user_password)
		if u:
				self.set_secure_cookie('user_id', str(u.key().id()))
				self.redirect('/blog') 
		else:
			self.render("login.html", **params)


class WelcomeHandler (Handler):

	def get(self):
		if self.user: #check if the user exists from the 'initialize' function
				self.render("welcome.html", username = self.user.username) #username from user object
		else:
				self.redirect('/signup')

class BlogHandler(Handler):   #'/blog' 

	def get(self):
		posts = Blog.all().order('-created').run(limit=10)
		self.render("blog.html", posts= posts)

	def post(self):

		subject = self.request.get("subject")
		content = self.request.get("content")
		user = self.user.username


		if subject and content:
			post = Blog(subject = subject, content = content, user = user)
			post.put()
			self.redirect('/blog')
		else:
			msg = "Enter both a subject and content"
			self.render("blog.html", error = msg)

import time 

class BlogJsonHandler(Handler):
	
	def get(self):

		#retrieve last 10 blog entry
		posts = Blog.all().order('-created').run(limit=10)
		 
		#put blog information into dictionary, store all dictionary in list 
		blogList = []
		for post in posts:
			time = post.created.strftime("%a %b %d %H:%M:%S %Y")   
			blogDict = dict(subject = post.subject, content = post.content, created = time)
			blogList.append(blogDict)	
		

		#write out list in HTML page
		self.write((blogList))


class BlogWithLocation(Handler):

	def get(self):
		self.write(self.request.remote_addr)
		self.write(repr(getCoors(self.request.remote_addr)))  
		posts = Blog.all().order('-created').run(limit=5)

		#cache all blog posts, reduce SQL request
		posts = list(posts)  

		#find which blogs have coordinates
		points = filter(None, (a.coors for a in posts))  #list of entity with coordinates

		img_url = None  
		if points:
			img_url = gmaps_img(points)  #get the img URL of all coordinates point

		self.render("blog.html", posts= posts, img_url = img_url)

	def post(self):

		subject = self.request.get("subject")
		content = self.request.get("content")
		user = self.user.username
		coors = getCoors(self.request.remote_addr)

		if subject and content:
			post = Blog(subject = subject, content = content, user = user, coors = coors)
			post.put()
			self.redirect('/blog')
		else:
			msg = "Enter both a subject and content"
			self.render("blog.html", error = msg)

class PostHandler(Handler):
	
	def get(self):
		self.render("post.html")

	def post(self):

		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			b = Blog(subject = subject, content = content)
			b.put()  #GAE assigned the object a key here 

			pageID = str(b.key().id())  #get the object's key as an integer 
			self.redirect('/blog/%s' %pageID) #redirect to the Permalink page
		else:
			error = "Please submit both a subject and content"
			self.render_front("post.html", subject = subject, 
							  			   content = content,
							               error = error)

class PermaLinkHandler(Handler):

	def get(self, page_id):
		key = db.Key.from_path('Blog', int(page_id))   #get the key from the UEL 
		blog = db.get(key)		#get the blog from the page key 

		if not blog:
			self.error(404)
			return

		self.render("blog_front.html", blog = blog)


class LogoutHandler(Handler):
	def get(self):
		self.logout()
		self.redirect('/signup')


app = webapp2.WSGIApplication([
	('/signup', Registration),
	('/login', Login), 
	('/welcome', WelcomeHandler),
	('/logout', LogoutHandler),
	('/blog/newpost', PostHandler),
	webapp2.Route(r'/blog/<page_id>', handler = PermaLinkHandler),
	('/blog', BlogHandler),
	('/blog.json', BlogJsonHandler), 
	('/blogLocation', BlogWithLocation)
	]
	, debug =True)




