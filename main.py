import jinja2   #had to add Jinja2 under libraries in app.yaml
 #Add this under librar in app.yaml

  #- name: jinja2                                                                  
  #version: latest 

import os     #this module lets us get the path to our 'templates' folder 
import webapp2

from google.appengine.ext import db  # import the database class 


#look for a templates folder inside of the applicaiton python package to find the html file
template_dir = os.path.join(os.path.dirname(__file__), 'templates')     

#create the template environement, FileSystemLoader is a Python package that helps load a template 
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#env = Environment(loader=PackageLoader('yourapplication', 'templates'))

class Handler(webapp2.RequestHandler):

	def write(self, *a , **kwargs):
		self.response.out.write(*a, **kwargs)  #write out template website with input variables

	def render(self, template, **kwargs):
		self.write(self.render_str(template, **kwargs))  

	def render_str(self, template, **kwargs):
		template = jinja_env.get_template(template)   #load template environment to website
		#Note: different render method, of the Template/Environment Class 
		return template.render(**kwargs)  # render/make and return the template website with input variables
	

#Art class represents submission art submission from user, inherits from db.Model class
class Art(db.Model):   
	#Create object's property of different data type
	title = db.StringProperty(required = True)   #variable created from Property constructor, 
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)  #create Time property at creation 


class MainPage (Handler):

	#Created this method to handle all page rendering for all cases, instead of individual call for render
	def render_front(self, title = "", art = "" , error = ""):     

		arts = db.GqlQuery("Select * From Art "       #get all Art object from the DataStore 
			                   "Order by created Desc")


		self.render("front.html", title = title, 
								  art = art, 
								  error = error,
								  arts = arts )  #render the page with all art from DataStore

	def get(self):
		self.render_front()

	def post(self):

		title = self.request.get('title')
		art = self.request.get('art')


		if title   and   art: 
			a = Art(title = title, art = art)   #create an Art object using form's input
			a.put()   #put the object in DataStore
			self.redirect('/')
		else:
			error = "You did not include both a title and an art"
			self.render_front( title = title,    #title is key argument, maps to html page {{title}}
							   art = art,        #art is key argument, maps to html page {{art}}
							   error = error)    #error is key argument, maps to html page {{error}}


app = webapp2.WSGIApplication([
	('/', MainPage),
	]
	, debug =True)




