# MethodOverrider

Method Overrider is a plugin for Burp Suite developed for helping the detection of the Method Override technique.

### Install
Make sure you have Jython installed in your environment. Then you just have to pull the source code and load it in Burp Extender

### Usage
After loading the extension, whenever you send a request in the Burp Repeater's context, the plugin will fuzz the request by adding the headers and/or parameters used by the Method Override technique. If the status code from the page is different than the original, the tool will issue an alert on the Dashboard and log the endpoint that has the Method Override technique enabled.
