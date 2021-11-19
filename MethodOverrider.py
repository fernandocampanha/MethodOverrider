from burp import IBurpExtender 
from burp import IProxyListener
from burp import IScanIssue
from burp import IHttpService

class BurpExtender(IBurpExtender, IProxyListener):

	def registerExtenderCallbacks(self, callbacks):

		self._callbacks = callbacks

		self.headers = ['X-Http-Method-Override', 'X-HTTP-Method-Override', 'X-Http-Method', 'X-HTTP-Method', 'X-Method-Override']
		
		self.parameters = ['_method', 'method', 'X-Http-Method-Override', 'X-HTTP-Method', 'X-Method-Override', 'httpMethod', '_HttpMethod']

		self.targets = []

		self.requests = []

		self.url = ""

		callbacks.setExtensionName("Method Overrider")
		
		self.helpers = callbacks.getHelpers()

		callbacks.registerProxyListener(self)
		
		return 

	def processProxyMessage(self, messageIsRequest, message):
		has = False
		history = []

		if(messageIsRequest):
			path = str(self.helpers.analyzeRequest(message.getMessageInfo().getRequest()).getHeaders()[0].split()[1])
			val = message.getMessageInfo().getHttpService().getProtocol() + "://" + message.getMessageInfo().getHttpService().getHost() + ":" + str(message.getMessageInfo().getHttpService().getPort()) + path
			self.url = val

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
							has = True
							break

				# Check the request headers
				if(has == False):
					hdr = self.helpers.bytesToString(message.getMessageInfo().getRequest()).split("\r\n")
					for j in hdr:
						for i in self.headers:
							if(j != '' and i in j.split()[0]):
						 		has = True
						 		break

		# Check the response headers
		else:
			if(self.url in self.requests):
				return
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
							has = True
							break

		if(has == True and not messageIsRequest):
			if(self.url in self.requests):
				return
			else:
				self.requests.append(self.url)
				history.append(message.getMessageInfo())
				issue = CustomScanIssue(message.getMessageInfo().getHttpService(), self.helpers.analyzeRequest(message.getMessageInfo()).getUrl(), history, "Possible HTTP Method Override detected", "This request seems to be using the HTTP Method Override technique", "Information", "Tentative", "This technique can be used to bypass some HTTP methods filter", "null", "null")
				self._callbacks.addScanIssue(issue)

class CustomScanIssue(IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence, background, remediation_detail, remediation_background):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity
		self._confidence = confidence

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		return None

	def getRemediationBackground(self):
		return None

	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		return None

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService