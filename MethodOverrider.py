from burp import IBurpExtender 
from burp import IHttpService
from threading import Thread
from burp import IHttpListener
from burp import IProxyListener
from burp import IParameter
from burp import IContextMenuFactory
from time import sleep
from java.util import ArrayList
from javax.swing import JMenuItem

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IContextMenuFactory):

	def registerExtenderCallbacks(self, callbacks):

		self._callbacks = callbacks

		self.headers = ['X-Http-Method-Override', 'X-HTTP-Method-Override', 'X-Http-Method', 'X-HTTP-Method', 'X-Method-Override']
		
		self.methods = ['GET', 'POST', 'PUT', 'HEAD','OPTIONS', 'TRACE', 'PURGE', 'PATCH', 'CONNECT']
		
		self.parameters = ['_method', 'method', 'X-Http-Method-Override', 'X-HTTP-Method', 'X-Method-Override', 'httpMethod', '_HttpMethod']

		self.status = [200, 201, 301, 302, 307, 308, 400, 401, 403, 404, 405, 501]

		self.targets = []

		self.requests = []

		self.check = False

		self.override_type = -1

		self.busy = False

		self.threads = []

		callbacks.setExtensionName("MethodOverrider")
		
		self.helpers = callbacks.getHelpers()

		callbacks.registerHttpListener(self)

		callbacks.registerProxyListener(self)

		callbacks.registerContextMenuFactory(self.createMenuItems)
		
		return 

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

		if(messageIsRequest and toolFlag == self._callbacks.TOOL_PROXY):
			self.threads.append(messageInfo)

			thread = Thread(target=self.freeRepeater)
			thread.daemon = True
			thread.start()
			
	def processProxyMessage(self, messageIsRequest, message):
		has = False
		if(messageIsRequest):
			path = str(self.helpers.analyzeRequest(message.getMessageInfo().getRequest()).getHeaders()[0].split()[1])
			val = message.getMessageInfo().getHttpService().getProtocol() + "://" + message.getMessageInfo().getHttpService().getHost() + ":" + str(message.getMessageInfo().getHttpService().getPort()) + path

			if(val in self.targets):
				return
			else:
				self.targets.append(val)
				request = self.helpers.bytesToString(message.getMessageInfo().getRequest())
				result = message.getMessageInfo()
				path = str(self.helpers.analyzeRequest(result.getRequest()).getHeaders()[0].split()[1])
				params = self.helpers.analyzeRequest(result.getRequest()).getParameters()
				
				# Check the parameters
				for j in params:
					for i in self.parameters:
						if(i == j.getName()):
							print("\nThe page '" + result.getHttpService().getProtocol() + "://" + result.getHttpService().getHost() + 
									":" + str(result.getHttpService().getPort()) + path + "' might have the method override technique enabled by using the parameter '" + i + "'")
							has = True
							break

				# Check the request headers
				if(has == False):
					hdr = self.helpers.bytesToString(message.getMessageInfo().getRequest()).split("\r\n")
					for j in hdr:
						for i in self.headers:
							if(j != '' and i in j.split()[0]):
						 		print("\nThe page '" + result.getHttpService().getProtocol() + "://" + result.getHttpService().getHost() + 
									":" + str(result.getHttpService().getPort()) + path + "' might have the method override technique enabled by using the header '" + i + ": " + j.split()[1] + "'")
						 		has = True
						 		break

		# Check the response headers
		else:
			data = []
			if(has == False):
				result = message.getMessageInfo()
				hdr = self.helpers.analyzeResponse(result.getResponse()).getHeaders()
				for i in hdr:
					if("Access-Control-Allow-Headers" in i or "Vary" in i):
						data = i.split()
						break
				if(len(data) == 0):
					return
				for j in data:
					for i in self.headers:
						if(i in j):
							print("\nThe page '" + result.getHttpService().getProtocol() + "://" + result.getHttpService().getHost() + ":" + 
								str(result.getHttpService().getPort()) + "' might have the method override technique enabled by using the header '" + i + "' detected in the response of the page")
							has = True
							break

		if(has == True):
			self._callbacks.issueAlert("Possible Http Method Override detected")

	def freeRepeater(self):

		if(self.busy == False):
			
			self.busy = True

			while(len(self.threads) > 0):
				
				messageInfo = self.threads[0]
				self.control_request = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), messageInfo.getRequest())
				self.initial_request = self.helpers.analyzeRequest(messageInfo.getHttpService(), self.control_request.getRequest())
				self.initial_response = self.helpers.analyzeResponse(self.control_request.getResponse())
				self.sendNewRequests(self.initial_request, messageInfo, self.initial_response)
				self.threads.pop(0)
			
		else:
			freeRepeater()

	def analyze_response(self, result, name, method):

		new_response = self.helpers.analyzeResponse(result.getResponse())
		status_code = new_response.getStatusCode()

		# Verify if the status code has changed
		if(status_code != self.initial_response.getStatusCode()):
			
			self.check  = True

			if(status_code in self.status):

				try:
					path = str(self.helpers.analyzeRequest(result.getRequest()).getHeaders()[0].split()[1])
					if(self.override_type == 0):
						print("\nThe page '" + result.getHttpService().getProtocol() + "://" + result.getHttpService().getHost() + 
							":" + str(result.getHttpService().getPort()) + path + "' might have the method override technique enabled by using the header '" + name + ": " + method + "'")
					elif(self.override_type == 1):
						if(len(result.getResponse()) != len(self.initial_result.getResponse())):
							print("\nThe page '" + result.getHttpService().getProtocol() + "://" + result.getHttpService().getHost() + 
								":" + str(result.getHttpService().getPort()) + path + "' might have the method override technique enabled")

					print("Remember to test using other HTTP methods!")
					self._callbacks.issueAlert("Possible Http Method Override detected")
					return True
				except:
					print("Something went wrong while trying to analyze the response")

		return False
	
	def sendWithHeaders(self, i, body):
		self.override_type = 0

		for header in self.headers:

			for method in self.methods:

				self.initial_headers.append(header + ": " + method)				
				self.initial_headers.append("")				
				self.initial_headers.append(self.helpers.bytesToString(body))
				new_request = self.helpers.buildHttpMessage(self.initial_headers, None)

				try:

					# sleep(0.05)
					result = self._callbacks.makeHttpRequest(i.getHttpService(), new_request)
					if(self.analyze_response(result, header, method) == True):
						return

				except:

					print("Something went wrong with " + header + ": " + method)
				
				self.initial_headers.pop()
				self.initial_headers.pop()
				self.initial_headers.pop()

	def sendWithParameter(self, i, body):
		self.override_type = 1
		initial_request = self.helpers.analyzeRequest(i.getRequest())
		params = initial_request.getParameters()

		for param in self.parameters:
			for method in self.methods:
				new_param = self.helpers.buildParameter(param, method, IParameter.PARAM_URL)
				new_request = self.helpers.addParameter(i.getRequest(), new_param)

			 	try:
					# sleep(0.05)
					result = self._callbacks.makeHttpRequest(i.getHttpService(), new_request)
					if(self.analyze_response(result, param, method) == True):
						return

				except:

					print("Something went wrong with " + header + ": " + method)
				

	def sendNewRequests(self, requestInfo, i, responseInfo):

		body = self.control_request.getRequest()[self.initial_request.getBodyOffset():]

		m = requestInfo.getMethod() 

		if(m == "GET"):
			newRequest = self.helpers.bytesToString(self.helpers.toggleRequestMethod(i.getRequest())).split("\r\n")

		elif(m != "POST"):
			try:
				newRequest = self.helpers.bytesToString(i.getRequest()).replace(m, "POST").split("\r\n")
				content_type = None
				newRequest.pop()
				newRequest.pop()
				for j in newRequest:
					if("content-type" in j.lower().split()[0]):
						content_type = j.split()[1]
					 	break
				
				if(content_type == None):
					for k in responseInfo.getHeaders():
						if("content-type" in k.lower()):
							content_type = k.split()[1]
							newRequest.append("Content-Type: " + content_type)

			except:
				print("Something went wrong while trying to change the request method")

		else:
			newRequest = self.helpers.bytesToString(i.getRequest()).split("\r\n")
		
		newRequest.pop()
		newRequest.pop()

		self.initial_headers = newRequest

		try:
			new_request = self.helpers.buildHttpMessage(self.initial_headers, None)
			self.initial_result = self._callbacks.makeHttpRequest(i.getHttpService(), new_request)
			self.initial_request = self.helpers.analyzeRequest(self.initial_result.getRequest())
			self.initial_response = self.helpers.analyzeResponse(self.initial_result.getResponse())

		except:
			print("Something went wrong while making the request")

		self.sendWithHeaders(i, body)

		# Just call the sendWithParameter if the header results are empty
		if(self.check == False):
			self.sendWithParameter(i, body)		

		self.check = False
		self.busy = False

	def doActiveScan(self, event):
		request = self.context.getSelectedMessages()
		for i in request:
			self.processHttpMessage(self.context.getToolFlag(), True, i)

	def createMenuItems(self, invocation):
		self.context = invocation
		menuList = ArrayList()
		menuItem = JMenuItem("Active scan", actionPerformed=self.doActiveScan)
		menuList.add(menuItem)
		return menuList
