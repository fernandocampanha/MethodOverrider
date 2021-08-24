from burp import IBurpExtender 
from burp import IHttpService
from threading import Thread
from burp import IHttpListener
from burp import IParameter
from java.util import ArrayList

class BurpExtender(IBurpExtender, IHttpListener):

	def registerExtenderCallbacks(self, callbacks):

		self._callbacks = callbacks

		self.headers = ['X-Http-Method-Override', 'X-HTTP-Method', 'X-Method-Override']
		
		self.methods = ['GET', 'POST', 'PUT', 'HEAD','DELETE','OPTIONS', 'TRACE', 'COPY', 'LOCK', 'MKCOL', 'MOVE',
						'PURGE', 'PROPFIND', 'PROPPATCH', 'UNLOCK', 'REPORT', 'MKACTIVITY', 'CHECKOUT', 'MERGE',
						'M-SEARCH', 'NOTIFY', 'SUBSCRIBE', 'UNSUBSCRIBE', 'PATCH', 'SEARCH', 'CONNECT']
		
		self.parameters = ['_method', 'method', 'X-Http-Method-Override', 'X-HTTP-Method', 'X-Method-Override']

		self.status = [200, 201, 301, 302, 307, 308, 400, 401, 403, 404, 405, 501]

		self.targets = []

		self.requests = []

		self.check = False

		self.override_type = -1

		callbacks.setExtensionName("MethodOverrider")
		
		self.helpers = callbacks.getHelpers()

		callbacks.registerHttpListener(self)

		return 

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		
		if(messageIsRequest):

			path = str(self.helpers.analyzeRequest(messageInfo.getRequest()).getHeaders()[0].split()[1])
			val = messageInfo.getHttpService().getProtocol() + "://" + messageInfo.getHttpService().getHost() + ":" + str(messageInfo.getHttpService().getPort()) + path

			if(val in self.targets):
				return

			else:		
				self.targets.append(val)
				if(toolFlag == self._callbacks.TOOL_REPEATER):
			
					self.control_request = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), messageInfo.getRequest())
					self.initial_request = self.helpers.analyzeRequest(messageInfo.getHttpService(), self.control_request.getRequest())
					self.initial_response = self.helpers.analyzeResponse(self.control_request.getResponse())
										
					thread = Thread(target=self.sendNewRequests, args=(self.initial_request, messageInfo, self.initial_response))
					thread.start()
					thread.join()


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
						print("The page '" + result.getHttpService().getProtocol() + "://" + result.getHttpService().getHost() + 
							":" + str(result.getHttpService().getPort()) + path + "' might have the method override technique enabled by using the header '" + name + ": " + method + "'")
					elif(self.override_type == 1):
						if(len(result.getResponse()) != len(self.initial_result.getResponse())):
							print("The page " + result.getHttpService().getProtocol() + "://" + result.getHttpService().getHost() + 
								":" + str(result.getHttpService().getPort()) + path + " might have the method override technique enabled")
				except:
					print("Something went wrong while trying to analyze the response")

			self._callbacks.issueAlert("Possible Http Method Override detected")


	def sendWithHeaders(self, i, body):
		self.override_type = 0

		for header in self.headers:

			for method in self.methods:

				self.initial_headers.append(header + ": " + method)				
				self.initial_headers.append("")				
				self.initial_headers.append(self.helpers.bytesToString(body))
				new_request = self.helpers.buildHttpMessage(self.initial_headers, None)

				try:

					result = self._callbacks.makeHttpRequest(i.getHttpService(), new_request)
					self.analyze_response(result, header, method)

				except:

					print("Deu bronca com o " + header + ": " + method)
				
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
					result = self._callbacks.makeHttpRequest(i.getHttpService(), new_request)
					
					self.analyze_response(result, param, method)

				except:

					print("Something went wrong with " + header + ": " + method)
				

	def sendNewRequests(self, requestInfo, i, responseInfo):

		body = self.control_request.getRequest()[self.initial_request.getBodyOffset():]

		m = requestInfo.getMethod() 

		if(m == "GET"):
			newRequest = self.helpers.bytesToString(self.helpers.toggleRequestMethod(i.getRequest())).split("\r\n")
			newRequest.pop()
			newRequest.pop()

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
			# Descobrir pq tem dois espacos a mais nos headers
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