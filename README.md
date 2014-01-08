![Alt text](https://raw.github.com/lettier/dnsclient/master/screenshot.jpg)

# DNS Client

This DNS client is similar in nature to `nslookup` but only deals with A records. Note that this DNS client does not use any DNS libraries but rather works directly at the [DNS protocol level](http://technet.microsoft.com/en-us/library/dd197470). Needs [Bitstring](http://pythonhosted.org/bitstring/#download) to construct the binary DNS packet.

_(C) 2014 David Lettier._  
http://www.lettier.com/