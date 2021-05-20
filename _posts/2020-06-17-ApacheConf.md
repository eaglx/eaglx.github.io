---
layout: post
title:  "Apache config template"
date:   2020-06-17 00:00:00 +0000
categories: Admin
---

This is the Apache server example configuration walkthrough. All instruction will be write in a global configuration file _apache2.conf_.

{% highlight config %}
ServerSignature Off
ServerTokens Full
DefaultRuntimeDir ${APACHE_RUN_DIR}
TraceEnable Off
Timeout 30
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
HostnameLookups Off
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn

# Include module configuration:
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

# Include list of ports to listen on
Include ports.conf
{% endhighlight %}

At the beginning, ServerSignature configures the footer on server-generated documents. ServerTokens configures the server http response header. For example Prod option orders the server to send "Server: Apache". I suggest to set Full because later we hide the server name via a mod_security. Also we define the directory where shm (shared memory routines - files where the configurations are stored) and other runtime files will be stored. Next we set a directive that overrides the behavior of TRACE for both the core server and mod_proxy. The default TraceEnable On permits TRACE requests per RFC 2616, which disallows any request body to accompany the request. TraceEnable Off causes the core server and mod_proxy to return a 405 error to the client. Timeout - the number of seconds before receives and sends time out. To mitigate Slow Loris attack and DoS, you can lower the default timeout (in seconds) value. Also we can control whether or not to allow persistent connections (more than one request per connection). 

MaxKeepAliveRequests - the maximum nimber of requests to allow during a persistent connection. Set to 0 to allow an unlimited amount, but it is recomended to leave this number high, for maximum performance. KeepAliveTimeout - number of seconds to wait for the next request from the same client on the same connection.

HostnameLookups - log the names of clients or just their IP addresses e.g., wwww.apache.org (on) or 111.111.111.111 (off). The default is off because it'd be overall better for the net if people had to konwingly turn this features on, since enabling it means that each client request will result in AT LEAST one lokup request to the nameserver. ErrorLog - the location of the error log file. LogLevel - control the severity of messages logged to the error_log.


{% highlight config %}
<Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>
<Directory /usr/share>
	AllowOverride None
	Require all granted
</Directory>
<Directory /var/www/>
	Options FollowSymLinks
	AllowOverride All
	Require all granted
<Directory>

AccessFileName .htaccess

<FilesMatch "^\.ht">
	Require all denied
</FilesMatch>
<FilesMatch "^\.git">
	Require all denied
<FilesMatch>
{% endhighlight %}

Above sets the default security model of the Apache2 HTTP server. It does not allow access to the root filesystem outside of /usr/share and /var/www. Also remove Indexes from Options to stop Apache listing directories and change AllowOverride from None to All to enable .htaccess. if you want to later configure some rules in .htaccess, you will most likely need to enable mod_rewrite: sudo a2enmod rewrite. AccessFileName - the name of the file to look for in each directory for additional configuration directives. Also next lines prevent .htaccess, .htpasswd and .git files from being viewed by Web clients.

{% highlight config %}
# The following directives define some format nicknames for use with a CustomLog directive
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

# Include generic snippets of statements
IncludeOptional conf-enabled/*.conf

# Include the virtual host configurations:
IncludeOptional sites-enabled/*.conf
{% endhighlight %}

To prevent clickjacking it will be used _X-Frame-Options_ to prevent clickjacking. The clickjacking is an attack that tricks a user into clicking a webpage element which is invisible or camouflage as another element. Below example clickjacking code.

{% highlight xml %}
<html>
    <head>
        <title>Test</title>
    </head>
    <body>
        <p>Test clickjacking</p>
        <iframe src="link">

        </iframe>
    </body>
</html>
{% endhighlight %}

To prevent clickjacking we can set X-Frame-Options:
* SAMEORIGIN - allow a page to be displayed in a frame on the same origin
* DENY - prevent a page displaying in a frame or iframe
* ALLOW-FROM uri - allow a page to be displayed only on the specified origin.

{% highlight config %}
Header always set X-Frame-Options "deny"
{% endhighlight %}

{% highlight config %}
LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
LoadModule cspnonce_module modules/mod_cspnonce.so

<IfModule mod_headers.c>
	Header always set X-Content-Type-Options "nosniff"
	Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=10886400; includeSubDomains; preload"
    
    Header always set Content-Security-Policy " TODO " 
	Header always set X-Content-Security-Policy " TODO " 
	Header set X-WebKit-CSP " TODO " 
</IfModule>
{% endhighlight %}

In above it load mod_headers and mod_cspnonce ([github.com mod_cspnonce](https://github.com/wyattoday/mod_cspnonce)). To prevent MSIE from interpreting files as something else than declared by the content type in the HTTP headers. Also X-XSS-Protection header can prevent some level of XSS attacks. There are following possible ways you can configure this header:
* 0 - XSS filter disabled
* 1 - XSS filter enabled and sanitized the page if attack detected
* 1;mode=block - XSS filter enabled and prevented rendering the page if attack detected.

Strict-Transport-Security - ensures the connection cannot be establish through an insecure HTTP connection. The max-age must be at least eighteen weeks = 10886400 seconds. Content Security Policy (CSP) - is a layer of security that helps to detect and mitigate certain types of attakcs e.g., Cross Site Scripting. CSP informs the browser that the only content it shuld be allowing for your site is content that is loaded from your own domain. When there is inline code then shuld be used CSP_NONCE. Add the CSP_NONCE to the "default-src". Example of using nonce in script:

{% highlight php %}
<?php
     // access the CSP nonce from a script
     $csp_nonce = $_SERVER['CSP_NONCE'];
?>
{% endhighlight %}

{% highlight javascript %}
<script nonce="<?= $_SERVER['CSP_NONCE'] ?>">
    var inline = 1;
</script>
{% endhighlight %}

{% highlight config %}
<IfModule mod_headers.c>
    Header always edit Set-Cookie (.*) "$1; HTTPOnly; Secure"
</IfModule>

RewriteEngine On
RewriteCond %{THE_REQUEST} !HTTP/1.1$
RewriteRule .* - [F]

SetEnvIf Origin "^http(s)?://(.+\.)?(somesite.com)$" origin_is=$0
Header always set Access-Control-Allow-Credentials true
Header always set Access-Control-Allow-Origin %{origin_is}e env=origin_is
{% endhighlight %}

In above code it is set cookie with HttpOnly and Secure flag. Also disalbe HTTP 1.0 protocol which has security weakness related to session hijacking. Then set environment variable Origin Also set timeouts for receiving HTTP request headers and the HTTP request body from a client. If a client fails to send header or body data within the configured time, A _408 REQUEST TIMEOUT_ error is sent by the server. The configuartion _RequestReadTimeout header=10-30,MinRate=300 body=10-30,MinRate=300_ gives the client a maximum of 10 seconds to start sending header data. The client must send header data at a transfer rate of 300 bytes per second and may do it for a maximum of 30 seconds. Additionally, the configuration also gives the client a maximum of 10 seconds to start sending body data. The client must send message body data at a transfer rate of 300 bytes per second and may do it for a maximum of 30 seconds.

The mod_evasive (sudo apt-get install libapache2-mod-evasive) provides evasive action in the vent of an HTTP DDoS attack or brute force attack. It is also designed to be a detection and network management tool:
* DOSHashTableSize - the hash table size defines the number of top-level nodes for each child's hash table. Increasing this number will privde faster performance by devreasing the number of iterations required to get to the record, but consume more memory for table space. You shuld increase this if you have a busy web server. The value you specify will automatically be tiered up to the next prime number in the primes list.
* DOSSiteCountPermalink - this is the threshold for the total number of requests for any object by the same client on the same listener per site interval. Once the threshold for that interval has been exceeded, the IP address of the client will be added to the blocking list.
* DOSPageInterval - the interval for the site count threshold; defaults to 1 second intervals.
* DOSBlockingPeriod - the blocking period is the amount of time (in secodns) that a client will be blocked for if they are added to the blocking list. During this time, all subsequent requests from the client will result in a 403 (FORBIDDEN) and the timer being reset (e.g. another 10 seconds).Since the timer is reset for every subsequent request, it is not necessary to have a long blocking period; in the event of a DoS attack,this timer will keep getting reset.
* DOSSystemCommand - if this value is set, the system command specified will be executed whenever an IP address becomes blacklisted.

{% highlight config %}
DOSHashTableSize 3097
DOSPageCount 2
DOSSiteCount 50
DOSPageInterval 2
DOSSiteInterval 1
DOSBlockingPeriod 60
DOSWhitelist 127.0.0.1
DOSWhitelist 127.0.0.*
{% endhighlight %}

The module mod_security2 - web application firewall [HTTP Request -> ModSecurity -> httpd]. To install sudo apt-get install libapache2-mod-security2. The rule engine divides requests into five phrases:
* REQUEST_HEADERS
* REQUEST_BODY
* RESPONSE_HEADERS
* RESPONSE_BODY
* LOGGING

The logging phase is special in that it will always be executed even if a request has been allowed or denied in one of the previous phases.Also, once the logging phase has started, you cannot perform any disruptive actions as the response has already been sent to the client.

{% highlight config %}
# Turn the filtering engine On or Off (old SecFilterEngine, new SecRuleEngine in security2)
SecRuleEngine On

# The audit engine works independently and  can be turned On of Off on the per-server or on the per-directory basis
SecAuditEngine RelevantOnly

# Turns on processing of HTTP request bodies. This allow us to inspect uploads done via POST requests.
# When this directive is enabled, ModSecurity will buffer the request body in memory and process it before
# giving Apache access to it for the remaining processing.
SecRequestBodyAccess On

# Alter the web server signature sent by Apache
SecServerSignature "My server"

# Deny requests without a host header
SecRule &REQUEST_HEADERS:Host "@eq 0" "phase:1,deny,id:'1'"

# Deny requests without an accept header
SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,deny,id:'2'"

# Deny request that don't use GET, HEAD or POST
SecRule REQUEST_METHOD !^(get|head|post)$ "phase:1,t:lowerCase,deny,id:'3'"

# Default action set, phase:2 - after the request body has been read.
SecDefaultAction "phase:1,deny,log,status:403"
SecDefaultAction "phase:2,deny,log,status:403"

# Block Linux system commans, program names when present in arguments.
SecRule ARGS "(rm|ls|kill|(send)?mail|cat|echo|/bin/|/etc/|/tmp/)" "deny,id:'4'"

# Prevent path traversal (..) attacks
SecRule REQUEST_URI "\.\./" "phase:1,deny,id:'5',t:urlDecode"

# Prevent XSS atacks (HTML/Javascript injection)
SecRule REQUEST_URI "&lt;(.|\n)+&gt;" "phase:1,deny,id:'6'"

# Prevent slow HTTP atacks, the rules identify when the Apache HTTP server triggers 
# a 408 status code and track how many times this happend. The module keeps the data in IP-based persistent sorage
# so it can be correlated across requests. If this event has happened more than 6 times in 40 seconds,
# subsequent requests from that IP address will be dropped for a given period of time, in this case: 5 minutes.
SecRule RESPONSE_STATUS "@streq 408" "phase:5,t:none,nolog,pass,setvar:ip.slow_dos_counter=+1, expirevar:ip.slow_dos_counter=40, id:'7'"
SecRule IP:SLOW_DOS_COUNTER "@gt 6" "phase:1,t:none,log,drop,msg:'Client Connection Dropped due to high number of slow DoS alerts', id:'8'"

# Maximum request body size we will accept for buffering. If you support file uploads 
# then the value given on the first line has to be as large as the largest file 
# you are willing to accept. The second value refers to the size of data, with files excluded. You want to keep that value as low as practical.
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072

# Store up to 128 KB of request body data in memory. When the multipart parser reaches this limit, 
# it will start usting your hard disk for storage. That is slow, but unavoidable.
SecRequestBodyInMemoryLimit 131072

# What do do if the request body size is above our configured limit.
SecRequestBodyLimitAction Reject

# Verify that we've correctly processed the request body. As a rule of thumb, when failing to process a request 
# body you shuld reject the request (when deployed in blocking mode) or log a high-severity alert 
# (when deployed in detection-only mode).
SecRule REQBODY_ERROR "!@eq 0" "id:'9', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"

# PCRE Tuning (limit the maximum amount of memory/time spent on trying to match
# some text to a pattern) - we want to avoid a potential RegEx DoS condition
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000

# Some internal errors will set flags in TX and we will need to look for these. 
# All of these are prefixed with "MSC_". The folowing flags currently exist: 
# MSC_PCRE_LIMITS_EXCEEDED: PCRE match limits were exceeded.
SecRule TX:/^MSC_/ "!@streq 0" "id:'10',phase:2,t:none,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"

# Which response MIME types do you want to inspect? You should adjust the configuration 
# below to catch documents but avoid static files (e.g., images and archives).
SecResponseBodyMimeType text/plain text/html text/xml

# Buffer response bodies of up to 512 KB in length
SecResponseBodyLimit 524288

# What happens when we encounter a response body larger than the configured limit? 
# By default, we process what we have and let the rest through (not break any legitimate pages).
SecResponseBodyLimitAction ProcessPartial

# The location where WAF stores temporary files (for example, when it needs to handle a file 
# upload that is larger than the configured limit).
SecTmpDir /tmp/

# The location where WAF will keep its persistent data.
SecDataDir /tmp/

# Log the transactions that are marked by a rule, as well as those that trigger a server error (exclude 404).
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABDEFHIJZ

# Log everything we know about transaction.
SecAuditLogType Serial

# Use a single file for logging. This is much easier to look at, but assumes 
# that you will use the audit log only ocassionally
SecAuditLog /var/log/apache2/modsec_audit.log

# Use the most commonly used application/x-www-form-urlencoded parameter separator.
SecArgumentSeparator &

# Settle on version 0 (zero) cookies, as that is what most applications use. 
# Using an incorrect cookie version may open your installation to evasion attacks.
SecCookieFormat 0

# Specify your Unicode Code Point. This mapping is used by the t:urlDecodeUni transformattion 
# function to properly map encoded data to your language.
SecUnicodeMapFile /etc/modsecurity/unicode.mapping

# This increases performance by cleaning out stale collection (block) entries.
SecUnicodeCodePage 20127
SecCollectionTimeout 600

# Rate limit requests to the server, if 50 requests in short period of a time, then pause for 50000ms.
SecAction initcol:ip=%{REMOTE_ADDR},pass,nolog,id:11
SecRule IP:IP_ADDR_COUNTER "@gt 50" "phase:2,pause:50000,deny,id:12,log,msg:'RATELIMITED BOT',status:429,setenv:RATELIMITED"
SecAction "phase:2,pass,setvar:ip.ip_addr_counter=+1,nolog,id:13"
SecAction "phase:5,deprecatevar:ip.ip_addr_counter=1/1,pass,nolog,id:14"
Header always set Retry-After "50" env=RATELIMITED
{% endhighlight %}

There is also the mod_qos (sudo apt-get install libapache2-mod-qos), which is needed when you are exposed directly to a user connection. Mitigate slow HTTP DoS attacks. The below configuration settings track up to 100,000 connections and limit requests to a maximum of 256 connections. In addition, the configuration limits each IP address to a maximum if 50 connections and disables HTTP KeepAlive when 180 connections are used (70% of the connections in this case). Finally, the configuration requires a minimum of 150 byte per second per connection and limits the connection to 1200 bytes per second when MaxClients is reached.

{% highlight config %}
QS_ClientEntries 100000
QS_SrvMaxConnPerIP 50
MaxClients 256
QS_SrvMaxConnClose 180
QS_SrvMinDataRate 150 1200
{% endhighlight %}