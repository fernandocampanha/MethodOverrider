from burp import IBurpExtender 
from burp import IHttpRequestResponse
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from javax.swing import JMenuItem
from burp import IHttpService
from threading import Thread
from burp import IHttpListener
from burp import ITab
from javax import swing
from java.awt import BorderLayout
from burp import IParameter
from burp import IResponseVariations

class BurpExtender(IBurpExtender, IHttpRequestResponse, IHttpService, IHttpListener, ITab, IParameter, IResponseVariations):

	def registerExtenderCallbacks(self, callbacks):

		self._callbacks = callbacks

		self.headers = ['X-Http-Method-Override', 'X-HTTP-Method', 'X-Method-Override']
		
		self.methods = ['GET', 'POST', 'PUT', 'HEAD','DELETE','OPTIONS', 'TRACE', 'COPY', 'LOCK', 'MKCOL', 'MOVE',
						'PURGE', 'PROPFIND', 'PROPPATCH', 'UNLOCK', 'REPORT', 'MKACTIVITY', 'CHECKOUT', 'MERGE',
						'M-SEARCH', 'NOTIFY', 'SUBSCRIBE', 'UNSUBSCRIBE', 'PATCH', 'SEARCH', 'CONNECT']
		
		self.parameters = ['_method', 'method', 'X-Http-Method-Override', 'X-HTTP-Method', 'X-Method-Override']

		self.status = [200, 201, 301, 302, 307, 308, 400, 401, 403, 404, 405, 501]
		# self.status = [200, 201, 301, 302, 307, 308, 501]

		self.targets = []

		self.results = []

		callbacks.setExtensionName("MethodOverrider")
		
		self.helpers = callbacks.getHelpers()

		callbacks.registerContextMenuFactory(self.createMenuItems)

		callbacks.registerHttpListener(self)

		# self.createTab()

		# callbacks.addSuiteTab(self)

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


	def analyze_response(self, result, method):
		responses = []
		for i in self.results:
			# responses.append()
			print(i)
		# print(responses)
		# new_response = self.helpers.analyzeResponse(result.getResponse())
		# status_code = new_response.getStatusCode()

		# # Verify if the status code has changed
		# if(status_code != self.initial_response.getStatusCode()):

		# 	if(status_code in self.status):
		# 		try:
		# 			# print("novo: " + str(status_code) + "original: " + str(self.initial_response.getStatusCode()))
		# 			self.results.append(str(status_code) + " for using " + method + " method")				
		# 		except:
		# 			print("Foi nao")
		# #		print(str(status_code) + " for using " + method + " method")


		# Verify if the size of response has changed

		#	if(len(result.getResponse()) != len(self.initial_result.getResponse())):
		#		print("The response body has different length \n")

	def sendWithHeaders(self, i, body):

		for header in self.headers:

			for method in self.methods:

				self.initial_headers.append(header + ": " + method)				
				self.initial_headers.append("")				
				self.initial_headers.append(self.helpers.bytesToString(body))
				new_request = self.helpers.buildHttpMessage(self.initial_headers, None)

				try:
					result = self._callbacks.makeHttpRequest(i.getHttpService(), new_request)
					self.results.append(result.getResponse())
					# self.analyze_response(result, method)

				except:

					print("Deu bronca com o " + header + ": " + method)
				
				self.initial_headers.pop()
				self.initial_headers.pop()
				self.initial_headers.pop()

	def sendWithParameter(self, i, body):
		initial_request = self.helpers.analyzeRequest(i.getRequest())
		params = initial_request.getParameters()

		for param in self.parameters:
			for method in self.methods:
				new_param = self.helpers.buildParameter(param, method, IParameter.PARAM_URL)
				new_request = self.helpers.addParameter(i.getRequest(), new_param)

			 	try:
					result = self._callbacks.makeHttpRequest(i.getHttpService(), new_request)
					# self.results.append(result.getResponse())
					print(self.helpers.bytesToString(result.getResponse()))
					# self.analyze_response(result, method)

				except:

					print("Deu bronca com o " + header + ": " + method)
				

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
				print("Deu ruim men")

		else:
			newRequest = self.helpers.bytesToString(i.getRequest()).split("\r\n")
			# Descobrir pq tem dois espacos a mais nos headers
			newRequest.pop()
			newRequest.pop()
			# print(newRequest)

		self.initial_headers = newRequest

		try:
			new_request = self.helpers.buildHttpMessage(self.initial_headers, None)
			self.initial_result = self._callbacks.makeHttpRequest(i.getHttpService(), new_request)
			self.initial_request = self.helpers.analyzeRequest(self.initial_result.getRequest())
			self.initial_response = self.helpers.analyzeResponse(self.initial_result.getResponse())

		except:
			print("foi nao")

		self.sendWithHeaders(i, body)
		# Just call the sendWithParameter if the header results are empty
		if(len(self.results) == 0):
			self.results = []
			self.sendWithParameter(i, body)	

		print("The results are:\n" + str(self.results))
		self.results = []


	def getRequest(self, event):
		
		item = self.context.getSelectedMessages()
		
		for i in item:
						
			self.control_request = self._callbacks.makeHttpRequest(i.getHttpService(), i.getRequest())
			self.initial_request = self.helpers.analyzeRequest(self.control_request.getRequest())
			self.initial_response = self.helpers.analyzeResponse(self.control_request.getResponse())

			thread = Thread(target=self.sendNewRequests, args=(self.initial_request, messageInfo, self.initial_response))
			thread.start()
			thread.join()

	def createMenuItems(self, invocation):
		
		self.context = invocation
		
		menuList = ArrayList()
		menuItem = JMenuItem("Send to Method Overrider", actionPerformed=self.getRequest)
		menuList.add(menuItem)
		
		return menuList			

	def getTabCaption(self):
		return "Method Overrider"
    
	def getUiComponent(self):
		return self.tab

	def encode(self, event):
		pass

	def createTab(self):

		self.tab = swing.JPanel(BorderLayout())

		textPanel = swing.JPanel()
		
		boxVertical = swing.Box.createVerticalBox()
		boxHorizontal = swing.Box.createHorizontalBox()
		textLabel = swing.JLabel("Text to be encoded/decoded/hashed")
		boxHorizontal.add(textLabel)
		boxVertical.add(boxHorizontal)

		boxHorizontal = swing.Box.createHorizontalBox()
		self.textArea = swing.JTextArea('', 6, 100)
		self.textArea.setLineWrap(True)
		boxHorizontal.add(self.textArea)
		boxVertical.add(boxHorizontal)

		textPanel.add(boxVertical)

		self.tab.add(textPanel, BorderLayout.NORTH) 

		tabbedPane = swing.JTabbedPane()
		self.tab.add("Center", tabbedPane);

		firstTab = swing.JPanel()
		firstTab.layout = BorderLayout()
		tabbedPane.addTab("Encode", firstTab)

		secondTab = swing.JPanel()
		secondTab.layout = BorderLayout()
		tabbedPane.addTab("Decode", secondTab)

		thirdTab = swing.JPanel()
		thirdTab.layout = BorderLayout()
		tabbedPane.addTab("Hash", thirdTab)

		# Panel for the encoders. Each label and text field
		# will go in horizontal boxes which will then go in 
		# a vertical box
		encPanel = swing.JPanel()
		boxVertical = swing.Box.createVerticalBox()

		# Add the vertical box to the Encode tab
		firstTab.add(boxVertical, "Center")