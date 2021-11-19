# Method Overrider

Method Overrider is a plugin for Burp Suite developed for helping the detection of the Method Override technique.

### Install
Make sure you have Jython installed in your environment. More information can be found in:

* https://portswigger.net/support/how-to-install-an-extension-in-burp-suite

Then you just have to pull the source code and load it in Burp Extender.

### Usage
After loading the extension, every request that goes through the proxy will be analyzed in search of the Method Override Technique.

Whenever it finds the Method Override header or parameter, it will add a scan issue to the issue activity. 
