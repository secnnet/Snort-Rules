# Rule to detect HTTP traffic to a known malicious domain:
alert tcp any any -> any any (msg:"Malicious HTTP traffic to known malicious domain"; flow:to_server,established; content:"Host: maliciousdomain.com"; http_header; sid:10001; rev:1;)

# Rule to detect SSH brute force attacks:
alert tcp any any -> any 22 (msg:"SSH Brute Force Attack"; flow:to_server,established; content:"ssh"; depth:3; content:"authentication failed"; sid:10002; rev:1;)

# Rule to detect SQL injection attacks:
alert tcp any any -> any any (msg:"Possible SQL Injection Attack"; flow:to_server,established; content:"' or 1=1--"; sid:10003; rev:1;)

# Rule to detect suspicious port scans:
alert tcp any any -> any any (msg:"Suspicious Port Scan"; flags:S; threshold: type both, count 5, seconds 60; sid:10004; rev:1;)

# Rule to detect DNS queries to known malicious domains:
alert udp any any -> any 53 (msg:"Malicious DNS query to known malicious domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; content:"|0c|maliciousdomain|03|com|00|"; sid:10005; rev:1;)

# Rule to detect HTTP requests with a high number of parameters:
alert tcp any any -> any any (msg:"HTTP Request with High Number of Parameters"; flow:to_server,established; http_method; content:"?"; http_uri; pcre:"/^([^\?\n]{0,255}\?){6,}/U"; sid:10006; rev:1;)

# This rule triggers an alert when an HTTP request with a high number of parameters is detected. In this example, the rule is set to detect requests with six or  parameters.

# Rule to detect FTP brute force attacks:
alert tcp any any -> any 21 (msg:"FTP Brute Force Attack"; flow:to_server,established; content:"USER "; depth:5; content:"PASS "; within:20; threshold: type both, track by_src, count 5, seconds 60; sid:10007; rev:1;)
# This rule triggers an alert when multiple failed login attempts are detected in a short period of time. The threshold parameter is used to limit the number of alerts generated.

# Rule to detect suspicious activity from known malicious IPs:
alert ip [known_malicious_ip]/32 any -> any any (msg:"Suspicious Activity from Known Malicious IP"; threshold: type both, track by_src, count 5, seconds 60; sid:10008; rev:1;)
# This rule triggers an alert when suspicious activity is detected from a known malicious IP address. The threshold parameter is used to limit the number of alerts generated.

# Rule to detect SSH traffic with invalid user names:
alert tcp any any -> any 22 (msg:"Invalid SSH User Name"; flow:to_server,established; content:"SSH-2.0-"; depth:9; content:"user "; depth:5; content:"invalid"; sid:10009; rev:1;)
# This rule triggers an alert when an SSH connection is attempted with an invalid user name.

# Rule to detect outgoing traffic to known malicious IP addresses:
alert ip any any -> [known_malicious_ip]/32 any (msg:"Outgoing Traffic to Known Malicious IP"; threshold: type both, track by_src, count 5, seconds 60; sid:10010; rev:1;)
# This rule triggers an alert when outgoing traffic to a known malicious IP address is detected. The threshold parameter is used to limit the number of alerts generated.

# Rule to detect DNS queries for known malicious domains:
alert udp any any -> any 53 (msg:"DNS Query for Known Malicious Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; content:"|07|malware|03|com|00|"; sid:10011; rev:1;)
# This rule triggers an alert when DNS queries for known malicious domains are detected.

# Rule to detect HTTP traffic to suspicious user-agents:
alert tcp any any -> any any (msg:"HTTP Traffic to Suspicious User-Agent"; flow:to_server,established; http_header; content:"User-Agent|3A 20|"; pcre:"/(\b(BlackWidow|wget|nikto|sqlmap|metasploit|curl|libwww-perl)\b)/i"; sid:10012; rev:1;)
# This rule triggers an alert when HTTP traffic to suspicious user-agents is detected. The rule uses a regular expression to match on known malicious user-agents.

# Rule to detect SQL injection attempts in HTTP requests:
alert tcp any any -> any any (msg:"SQL Injection Attack Detected"; flow:to_server,established; content:"|3D|"; http_uri; pcre:"/(\b(union|select|from|where|information_schema|database|benchmark|sleep)\b)/i"; sid:10013; rev:1;)
# This rule triggers an alert when SQL injection attempts are detected in HTTP requests. The rule uses a regular expression to match on known SQL injection keywords.

# Rule to detect SSH traffic from unknown source IPs:
alert tcp any [!known_good_ips]/24 -> any 22 (msg:"SSH Traffic from Unknown Source IP"; flow:to_server,established; content:"SSH-2.0-"; depth:9; sid:10014; rev:1;)
# This rule triggers an alert when SSH traffic is detected from an unknown source IP address. The rule uses the negation operator to exclude known good IP addresses from triggering an alert.

# Rule to detect suspicious activity in FTP data transfers:
alert tcp any any -> any 21 (msg:"Suspicious Activity in FTP Data Transfer"; flow:to_server,established; content:"STOR"; depth:4; pcre:"/(exec|system|shell|bin|sh|bash)/i"; sid:10015; rev:1;)
# This rule triggers an alert when suspicious activity is detected in FTP data transfers. The rule uses a regular expression to match on known malicious commands.

# Rule to detect HTTP traffic with large POST requests:
alert tcp any any -> any any (msg:"Large HTTP POST Request Detected"; flow:to_server,established; http_method; content:"POST"; http_uri; content:"Content-Length"; depth:15; pcre:"/^Content-Length\s*:\s*[0-9]{4,}$/"; threshold:type both,track by_src,count 5,seconds 60; sid:10016; rev:1;)
# This rule triggers an alert when large HTTP POST requests are detected. The rule uses a regular expression to match on the "Content-Length" header and sets a threshold to limit the number of alerts generated.

# Rule to detect incoming traffic to high-numbered ports:
alert tcp any any -> any [1024:65535] (msg:"Incoming Traffic to High-Numbered Port"; threshold:type both,track by_src,count 5,seconds 60; sid:10017; rev:1;)
# This rule triggers an alert when incoming traffic to high-numbered ports is detected. The rule sets a threshold to limit the number of alerts generated.

# Rule to detect HTTP traffic to suspicious file extensions:
alert tcp any any -> any any (msg:"HTTP Traffic to Suspicious File Extension"; flow:to_server,established; content:".php"; http_uri; pcre:"/\.((php|aspx|jsp|cgi)|\d{3,4})/i"; sid:10018; rev:1;)
# This rule triggers an alert when HTTP traffic to suspicious file extensions is detected. The rule uses a regular expression to match on known malicious file extensions.

# Rule to detect ICMP echo requests from external sources:
alert icmp [!10.0.0.0/8, !172.16.0.0/12, !192.168.0.0/16] any -> any any (msg:"ICMP Echo Request from External Source"; sid:10019; rev:1;)
# This rule triggers an alert when ICMP echo requests from external sources are detected. The rule uses the negation operator to exclude internal IP ranges from triggering an alert.

# Rule to detect DNS queries with long domain names:
alert udp any any -> any 53 (msg:"DNS Query with Long Domain Name"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/^\d+[a-zA-Z0-9\-\.]{256,}\.\w{2,}$/U"; sid:10020; rev:1;)
# This rule triggers an alert when DNS queries with long domain names are detected. The rule uses a regular expression to match on domain names with  than 255 characters.

# Rule to detect SSH traffic to known malicious IP addresses:
alert tcp any any -> [known_malicious_ip]/32 22 (msg:"SSH Traffic to Known Malicious IP Address"; sid:10021; rev:1;)
# This rule triggers an alert when SSH traffic to known malicious IP addresses is detected.

# Rule to detect HTTP traffic to suspicious IP addresses:
alert tcp any any -> [suspicious_ip_addresses]/32 any (msg:"HTTP Traffic to Suspicious IP Address"; flow:to_server,established; content:"HTTP/1."; content:"Host|3A 20|"; within:25; pcre:"/(\b(192\.168|10\.0)\b)/"; sid:10022; rev:1;)
# This rule triggers an alert when HTTP traffic to suspicious IP addresses is detected. The rule uses a regular expression to match on known malicious IP addresses.

# Rule to detect DNS queries with invalid characters:
alert udp any any -> any 53 (msg:"DNS Query with Invalid Characters"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/[\x00-\x1f\x7f]/"; sid:10023; rev:1;)
# This rule triggers an alert when DNS queries with invalid characters are detected. The rule uses a regular expression to match on characters that are not allowed in DNS queries.

# Rule to detect HTTP traffic with large cookie headers:
alert tcp any any -> any any (msg:"HTTP Traffic with Large Cookie Header"; flow:to_server,established; http_header; content:"Cookie|3A 20|"; pcre:"/Cookie\s*:\s*(\w+\=[^\;]*\;){10,}/i"; sid:10024; rev:1;)
# This rule triggers an alert when HTTP traffic with large cookie headers is detected. The rule uses a regular expression to match on cookie headers with  than 10 parameters.

# Rule to detect FTP traffic to suspicious file extensions:
alert tcp any any -> any 21 (msg:"FTP Traffic to Suspicious File Extension"; flow:to_server,established; content:"STOR "; depth:5; pcre:"/\.(php|aspx|jsp|cgi)$/i"; sid:10025; rev:1;)
# This rule triggers an alert when FTP traffic to suspicious file extensions is detected. The rule uses a regular expression to match on known malicious file extensions.

# Rule to detect HTTP traffic with suspicious user-agent values:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious User-Agent"; flow:to_server,established; http_header; content:"User-Agent|3A 20|"; pcre:"/(bot|crawler|scanner|spider|wget|nikto|sqlmap|curl|libwww-perl)/i"; sid:10026; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious user-agent values is detected. The rule uses a regular expression to match on known malicious user-agent strings.

# Rule to detect SMTP traffic to known malicious domains:
alert tcp any any -> any 25 (msg:"SMTP Traffic to Known Malicious Domain"; flow:to_server,established; content:"RCPT TO|3A|"; pcre:"/(administrator|info|support|webmaster)@maliciousdomain\.com/i"; sid:10027; rev:1;)
# This rule triggers an alert when SMTP traffic to known malicious domains is detected. The rule uses a regular expression to match on known malicious email addresses.

# Rule to detect HTTP traffic to known phishing URLs:
alert tcp any any -> any any (msg:"HTTP Traffic to Known Phishing URL"; flow:to_server,established; content:"Host|3A 20|"; http_header; pcre:"/\b(phishing|login|account|security)\b/i"; sid:10028; rev:1;)
# This rule triggers an alert when HTTP traffic to known phishing URLs is detected. The rule uses a regular expression to match on known phishing keywords.

# Rule to detect suspicious ICMP traffic:
alert icmp any any -> any any (msg:"Suspicious ICMP Traffic"; content:"|08 00|"; dsize:0; threshold:type both,track by_src,count 5,seconds 60; sid:10029; rev:1;)
# This rule triggers an alert when suspicious ICMP traffic is detected. The rule uses a threshold to limit the number of alerts generated.

# Rule to detect DNS queries with long label lengths:
alert udp any any -> any 53 (msg:"DNS Query with Long Label Lengths"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\w{63,}\./U"; sid:10030; rev:1;)
# This rule triggers an alert when DNS queries with label lengths greater than 63 characters are detected. The rule uses a regular expression to match on long label lengths.

# Rule to detect SQL injection attempts using the "OR" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using OR Keyword"; flow:to_server,established; content:"' or "; nocase; sid:10031; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "OR" keyword are detected.

# Rule to detect HTTP traffic with large file uploads:
alert tcp any any -> any any (msg:"HTTP Traffic with Large File Upload"; flow:to_server,established; http_method; content:"POST"; http_uri; content:"Content-Length"; depth:15; pcre:"/^Content-Length\s*:\s*[0-9]{6,}$/"; threshold:type both,track by_src,count 5,seconds 60; sid:10032; rev:1;)
# This rule triggers an alert when HTTP traffic with large file uploads is detected. The rule sets a threshold to limit the number of alerts generated.

# Rule to detect SSH traffic to non-standard ports:
alert tcp any any -> any [!22] (msg:"SSH Traffic to Non-Standard Port"; flow:to_server,established; content:"SSH-2.0-"; depth:9; sid:10033; rev:1;)
# This rule triggers an alert when SSH traffic to non-standard ports is detected. The rule uses the negation operator to exclude port 22 from triggering an alert.

# Rule to detect DNS queries with long domain name labels:
alert udp any any -> any 53 (msg:"DNS Query with Long Domain Name Labels"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\b(\w{64,})\./U"; sid:10034; rev:1;)
# This rule triggers an alert when DNS queries with label lengths greater than 63 characters are detected. The rule uses a regular expression to match on long label lengths.

# Rule to detect suspicious traffic to known C&C servers:
alert tcp any any -> [known_cc_servers]/32 any (msg:"Suspicious Traffic to Known C&C Server"; threshold:type both,track by_src,count 5,seconds 60; sid:10035; rev:1;)
# This rule triggers an alert when suspicious traffic to known command and control (C&C) servers is detected. The rule uses a threshold to limit the number of alerts generated.

# Rule to detect HTTP traffic with suspicious referer headers:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious Referer Header"; flow:to_server,established; http_header; content:"Referer|3A 20|"; pcre:"/\b(phishing|login|account|security)\b/i"; sid:10036; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious referer headers is detected. The rule uses a regular expression to match on known phishing keywords.

# Rule to detect SMTP traffic to unknown domains:
alert tcp any any -> any 25 (msg:"SMTP Traffic to Unknown Domain"; flow:to_server,established; content:"RCPT TO|3A|"; pcre:"/@(?!hotmail\.com|gmail\.com|yahoo\.com|aol\.com|outlook\.com|protonmail\.com)[a-z0-9.-]+\.[a-z]{2,}$/i"; sid:10037; rev:1;)
# This rule triggers an alert when SMTP traffic to unknown domains is detected. The rule uses a regular expression to match on email addresses that do not belong to known email providers.

# Rule to detect HTTP traffic with suspicious query parameters:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious Query Parameter"; flow:to_server,established; http_uri; pcre:"/\b(script|alert|confirm|prompt|onclick)\b/i"; sid:10038; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious query parameters is detected. The rule uses a regular expression to match on known malicious keywords.

# Rule to detect suspicious TCP traffic to high-numbered ports:
alert tcp any any -> any [1024:65535] (msg:"Suspicious TCP Traffic to High-Numbered Port"; threshold:type both,track by_src,count 5,seconds 60; sid:10039; rev:1;)
# This rule triggers an alert when suspicious TCP traffic to high-numbered ports is detected. The rule uses a threshold to limit the number of alerts generated.

# Rule to detect HTTP traffic with multiple user-agent headers:
alert tcp any any -> any any (msg:"HTTP Traffic with Multiple User-Agent Headers"; flow:to_server,established; http_header; pcre:"/^User-Agent\s*:\s*([^\r\n]+)(?:\r\nUser-Agent\s*:\s*[^\r\n]+)+$/"; sid:10040; rev:1;)
# This rule triggers an alert when HTTP traffic with multiple user-agent headers is detected. The rule uses a regular expression to match on multiple occurrences of the "User-Agent" header.

# Rule to detect SQL injection attempts using the "UNION" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using UNION Keyword"; flow:to_server,established; content:"' union "; nocase; sid:10041; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "UNION" keyword are detected.

# Rule to detect HTTP traffic to suspicious URL paths:
alert tcp any any -> any any (msg:"HTTP Traffic to Suspicious URL Path"; flow:to_server,established; http_uri; pcre:"/\/(\w+\.\w{2,}|index\.\w{2,}|phpmyadmin|admin|wp-admin)/i"; sid:10042; rev:1;)
# This rule triggers an alert when HTTP traffic to suspicious URL paths is detected. The rule uses a regular expression to match on known malicious URL paths.

# Rule to detect SSH traffic with multiple authentication failures:
alert tcp any any -> any 22 (msg:"SSH Traffic with Multiple Authentication Failures"; flow:to_server,established; content:"authentication failure"; nocase; threshold:type threshold,track by_src,count 5,seconds 60; sid:10043; rev:1;)
# This rule triggers an alert when SSH traffic with multiple authentication failures is detected. The rule uses a threshold to limit the number of alerts generated.

# Rule to detect DNS queries for known malicious domains:
alert udp any any -> any 53 (msg:"DNS Query for Known Malicious Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\b(malware|spyware|trojan|phishing)\b/i"; sid:10044; rev:1;)
# This rule triggers an alert when DNS queries for known malicious domains are detected. The rule uses a regular expression to match on known malicious domain names.

# Rule to detect HTTP traffic with suspicious user credentials:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious User Credentials"; flow:to_server,established; http_header; content:"Authorization|3A 20|"; pcre:"/(\badmin\b|\broot\b)/i"; sid:10045; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious user credentials is detected. The rule uses a regular expression to match on known malicious usernames.

# Rule to detect SQL injection attempts using the "SELECT" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using SELECT Keyword"; flow:to_server,established; content:"' select "; nocase; sid:10046; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "SELECT" keyword are detected.

# Rule to detect HTTP traffic to suspicious domain names:
alert tcp any any -> any any (msg:"HTTP Traffic to Suspicious Domain Name"; flow:to_server,established; content:"Host|3A 20|"; http_header; pcre:"/(\bmalware\b|\btrojan\b|\bspam\b|\bscam\b|\bspyware\b)/i"; sid:10047; rev:1;)
# This rule triggers an alert when HTTP traffic to suspicious domain names is detected. The rule uses a regular expression to match on known malicious domain names.

# Rule to detect SSH traffic with long banner strings:
alert tcp any any -> any 22 (msg:"SSH Traffic with Long Banner String"; flow:to_server,established; content:"SSH-2.0-"; depth:9; content:"|0d 0a|"; distance:1; within:100; sid:10048; rev:1;)
# This rule triggers an alert when SSH traffic with long banner strings is detected. The rule uses the "distance" and "within" options to match on a banner string up to 100 characters in length.

# Rule to detect DNS queries for known malicious IP addresses:
alert udp any any -> any 53 (msg:"DNS Query for Known Malicious IP Address"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\b(5\.5\.5\.5|127\.0\.0\.1)\b/"; sid:10049; rev:1;)
# This rule triggers an alert when DNS queries for known malicious IP addresses are detected. The rule uses a regular expression to match on known malicious IP addresses.

# Rule to detect HTTP traffic with suspicious file extensions:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious File Extension"; flow:to_server,established; http_uri; pcre:"/\.(php|aspx|jsp|cgi)$/i"; sid:10050; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious file extensions is detected. The rule uses a regular expression to match on known malicious file extensions.

# Rule to detect SQL injection attempts using the "UPDATE" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using UPDATE Keyword"; flow:to_server,established; content:"' update "; nocase; sid:10051; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "UPDATE" keyword are detected.

# Rule to detect HTTP traffic with suspicious cookie values:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious Cookie Value"; flow:to_server,established; http_header; content:"Cookie|3A 20|"; pcre:"/(\busername\b|\bpassword\b|\bsessionid\b)/i"; sid:10052; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious cookie values is detected. The rule uses a regular expression to match on known malicious cookie names.

# Rule to detect SSH traffic with invalid protocol version strings:
alert tcp any any -> any 22 (msg:"SSH Traffic with Invalid Protocol Version String"; flow:to_server,established; content:"SSH-"; depth:4; pcre:"/^(SSH-\d\.\d-[\w\s]+)/"; content:"|0d 0a|"; within:100; sid:10053; rev:1;)
# This rule triggers an alert when SSH traffic with invalid protocol version strings is detected. The rule uses regular expressions and the "within" option to match on a banner string up to 100 characters in length.

# Rule to detect DNS queries for known sinkhole domains:
alert udp any any -> any 53 (msg:"DNS Query for Known Sinkhole Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\.sinkhole$/i"; sid:10054; rev:1;)
# This rule triggers an alert when DNS queries for known sinkhole domains are detected. The rule uses a regular expression to match on known sinkhole domain names.

# Rule to detect HTTP traffic with suspicious file names:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious File Name"; flow:to_server,established; http_uri; pcre:"/(\bconfig\b|\bpasswd\b|\b\.htaccess\b)/i"; sid:10055; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious file names is detected. The rule uses a regular expression to match on known malicious file names.

# Rule to detect SQL injection attempts using the "INSERT" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using INSERT Keyword"; flow:to_server,established; content:"' insert "; nocase; sid:10056; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "INSERT" keyword are detected.

# Rule to detect HTTP traffic with suspicious HTTP methods:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious HTTP Method"; flow:to_server,established; http_method; content:"PUT"; nocase; sid:10057; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious HTTP methods is detected. The rule uses the "nocase" option to match on the "PUT" method regardless of case.

# Rule to detect SSH traffic with suspicious user credentials:
alert tcp any any -> any 22 (msg:"SSH Traffic with Suspicious User Credentials"; flow:to_server,established; content:"ssh_userauth"; nocase; content:"password|3A|"; nocase; pcre:"/(\badmin\b|\broot\b)/i"; sid:10058; rev:1;)
# This rule triggers an alert when SSH traffic with suspicious user credentials is detected. The rule uses regular expressions and the "nocase" option to match on known malicious usernames and password fields.

# Rule to detect DNS queries for known malicious subdomains:
alert udp any any -> any 53 (msg:"DNS Query for Known Malicious Subdomain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\.(\bmalware\b|\btrojan\b|\bspam\b|\bscam\b|\bspyware\b)/i"; sid:10059; rev:1;)
# This rule triggers an alert when DNS queries for known malicious subdomains are detected. The rule uses a regular expression to match on known malicious subdomain names.

# Rule to detect HTTP traffic with suspicious HTTP response codes:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious HTTP Response Code"; flow:established,from_server; http_stat_code; content:"200"; nocase; threshold:type threshold,track by_src,count 5,seconds 60; sid:10060; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious HTTP response codes is detected. The rule uses the "nocase" option to match on the "200" response code regardless of case and sets a threshold to limit the number of alerts generated.

# Rule to detect SQL injection attempts using the "DELETE" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using DELETE Keyword"; flow:to_server,established; content:"' delete "; nocase; sid:10061; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "DELETE" keyword are detected.

# Rule to detect HTTP traffic with suspicious user-agent strings:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious User-Agent String"; flow:to_server,established; http_header; content:"User-Agent|3A 20|"; pcre:"/(\bPython\b|\bcurl\b)/i"; sid:10062; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious user-agent strings is detected. The rule uses a regular expression to match on known malicious user-agent strings.

# Rule to detect SSH traffic with long password strings:
alert tcp any any -> any 22 (msg:"SSH Traffic with Long Password String"; flow:to_server,established; content:"ssh_userauth"; nocase; content:"password|3A|"; nocase; pcre:"/password.{100,}/"; sid:10063; rev:1;)
# This rule triggers an alert when SSH traffic with long password strings is detected. The rule uses a regular expression to match on a password string of 100 characters or more.

# Rule to detect DNS queries for known malicious TLDs:
alert udp any any -> any 53 (msg:"DNS Query for Known Malicious TLD"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\.(\btk|\bcf|\bgq|\bml|\bga|\bgdn|\bla|\bcu|\blol|\bto|\bgl|\bgp|\bwin)/i"; sid:10064; rev:1;)
# This rule triggers an alert when DNS queries for known malicious top-level domains (TLDs) are detected. The rule uses a regular expression to match on known malicious TLDs.

# Rule to detect HTTP traffic with suspicious HTTP request methods:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious HTTP Request Method"; flow:to_server,established; http_method; pcre:"/(\bDELETE\b|\bTRACE\b|\bCONNECT\b)/i"; sid:10065; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious HTTP request methods is detected. The rule uses a regular expression to match on known malicious HTTP request methods.

# Rule to detect SQL injection attempts using the "DROP" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using DROP Keyword"; flow:to_server,established; content:"' drop "; nocase; sid:10066; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "DROP" keyword are detected.

# Rule to detect HTTP traffic with suspicious referrer headers:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious Referrer Header"; flow:to_server,established; http_header; content:"Referer|3A 20|"; pcre:"/(\bmalware\b|\btrojan\b|\bspam\b|\bscam\b|\bspyware\b)/i"; sid:10067; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious referrer headers is detected. The rule uses a regular expression to match on known malicious referrer header values.

# Rule to detect SSH traffic with suspicious command strings:
alert tcp any any -> any 22 (msg:"SSH Traffic with Suspicious Command String"; flow:to_server,established; content:"|20 3a 20|"; pcre:"/(\bping\b|\bnc\b|\btelnet\b)/i"; sid:10068; rev:1;)
# This rule triggers an alert when SSH traffic with suspicious command strings is detected. The rule uses a regular expression to match on known malicious command strings.

# Rule to detect DNS queries for known malicious domains with unusual TLDs:
alert udp any any -> any 53 (msg:"DNS Query for Known Malicious Domain with Unusual TLD"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\.(\btop|\btoday|\blive|\bxyz|\bwin|\bclub)\b/i"; sid:10069; rev:1;)
# This rule triggers an alert when DNS queries for known malicious domains with unusual TLDs are detected. The rule uses a regular expression to match on known malicious domain names with unusual TLDs.

# Rule to detect HTTP traffic with suspicious content length values:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious Content Length Value"; flow:established,from_server; http_header; content:"Content-Length|3A 20|"; pcre:"/^Content-Length\:\s*(\d+)\s*$/i"; content:"|0d 0a|"; within:100; threshold:type threshold,track by_src,count 5,seconds 60; sid:10070; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious content length values is detected. The rule uses a regular expression to match on known malicious content length values and sets a threshold to limit the number of alerts generated.

# Rule to detect SQL injection attempts using the "TRUNCATE" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using TRUNCATE Keyword"; flow:to_server,established; content:"' truncate "; nocase; sid:10071; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "TRUNCATE" keyword are detected.

# Rule to detect HTTP traffic with suspicious URL paths:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious URL Path"; flow:to_server,established; http_uri; content:"|2F|..|2F|"; nocase; sid:10072; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious URL paths is detected. The rule uses the "nocase" option to match on the ".." directory traversal sequence.

# Rule to detect SSH traffic with suspicious SSH key exchange strings:
alert tcp any any -> any 22 (msg:"SSH Traffic with Suspicious SSH Key Exchange String"; flow:to_server,established; content:"SSH-2.0-"; depth:9; content:"diffie-hellman-group1-sha1,"; nocase; sid:10073; rev:1;)
# This rule triggers an alert when SSH traffic with suspicious SSH key exchange strings is detected. The rule uses the "nocase" option to match on the "diffie-hellman-group1-sha1" key exchange algorithm.

# Rule to detect DNS queries for known malicious subnets:
alert udp any any -> any 53 (msg:"DNS Query for Known Malicious Subnet"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/(\b192\.168\.|\b10\.|\b172\.(1[6-9]|2\d|3[01])\.)/"; sid:10074; rev:1;)
# This rule triggers an alert when DNS queries for known malicious subnets are detected. The rule uses a regular expression to match on known malicious subnet ranges.

# Rule to detect HTTP traffic with suspicious query strings:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious Query String"; flow:to_server,established; http_uri; pcre:"/\?(.*[\x00-\x20"\']+|.*select.*)/i"; sid:10075; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious query strings is detected. The rule uses a regular expression to match on known malicious query strings.

# Rule to detect SQL injection attempts using the "ALTER" keyword:
alert tcp any any -> any any (msg:"SQL Injection Attempt Using ALTER Keyword"; flow:to_server,established; content:"' alter "; nocase; sid:10076; rev:1;)
# This rule triggers an alert when SQL injection attempts using the "ALTER" keyword are detected.

# Rule to detect HTTP traffic with suspicious user-agent values:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious User-Agent Value"; flow:to_server,established; http_header; content:"User-Agent|3A 20|"; nocase; pcre:"/(\bmasscan\b|\bnikto\b|\bburp\b|\bdirb\b)/i"; sid:10077; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious user-agent values is detected. The rule uses a regular expression to match on known malicious user-agent values.

# Rule to detect SSH traffic with unusual channel open requests:
alert tcp any any -> any 22 (msg:"SSH Traffic with Unusual Channel Open Request"; flow:to_server,established; content:"ssh_channel_open_request"; nocase; content:"subsystem|3A|"; nocase; pcre:"/(\bsudo\b|\bsh\b|\bbash\b|\bzsh\b|\bksh\b)/i"; sid:10078; rev:1;)
# This rule triggers an alert when SSH traffic with unusual channel open requests is detected. The rule uses regular expressions and the "nocase" option to match on known malicious channel open requests and subsystem names.

# Rule to detect DNS queries for known malicious domains with numerical TLDs:
alert udp any any -> any 53 (msg:"DNS Query for Known Malicious Domain with Numerical TLD"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; pcre:"/\.(\b1|\b2|\b3|\b4|\b5|\b6|\b7|\b8|\b9|\b0)\b/"; sid:10079; rev:1;)
# This rule triggers an alert when DNS queries for known malicious domains with numerical TLDs are detected. The rule uses a regular expression to match on known malicious domain names with numerical TLDs.

# Rule to detect HTTP traffic with suspicious HTTP version strings:
alert tcp any any -> any any (msg:"HTTP Traffic with Suspicious HTTP Version String"; flow:to_server,established; http_header; content:"HTTP/"; pcre:"/^(HTTP\/1\.0|HTTP\/0\.9)/"; sid:10080; rev:1;)
# This rule triggers an alert when HTTP traffic with suspicious HTTP version strings is detected. The rule uses regular expressions to match on known malicious HTTP version strings.

