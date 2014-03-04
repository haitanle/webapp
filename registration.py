import jinja2   #had to add Jinja2 under libraries in app.yaml
 #Add this under librar in app.yaml

  #- name: jinja2                                                                  
  #version: latest 

import os     #this module lets us get the path to our 'templates' folder 
import webapp2


#look for a templates folder inside of the applicaiton python package to find the html file
template_dir = os.path.join(os.path.dirname(__file__), 'templates')     

#create the template environement, FileSystemLoader is a Python package that helps load a template 
env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#env = Environment(loader=PackageLoader('yourapplication', 'templates'))

class Handler(webapp2.RequestHandler):

	def write(self, *a , **kwargs):
		self.response.out.write(*a, **kwargs)  #write out template website with input variables

	def render(self, template, **kwargs):
		template = env.get_template(template)   #load template environment to website
		self.write(self.render_str(template, **kwargs))  

	def render_str(self, template, **kwargs):
		return template.render(**kwargs)  # render/make the template website with input variables
	
	


class MainPage (Handler):

	def get(self):
		self.render("front.html")


app = webapp2.WSGIApplication([
	('/', MainPage),
	]
	, debug =True)




