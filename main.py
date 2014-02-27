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
		self.response.headers["Content-Type"] = "text/plain"   
		visits = self.request.cookies.get('visits','0')  #get cookie 'visits' from the browser, 0 if None

		if visits.isdigit():   #allow to convert 'visits' to a string 
			visits = int(visits) + 1   #increment 'visits' each time it is visited
		else:
			visits = 0   #if 'visits' is 'None'

		self.response.headers.add_header('Set-Cookie', 'visits=%s' %visits)   #reset the cookie 'visits' in the browser

		self.write("You have visited this site %s times" %visits)    #print 'visits' count

		


app = webapp2.WSGIApplication([
	('/', MainPage),
	]
	, debug =True)




