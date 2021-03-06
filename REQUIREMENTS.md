# Owasp to CVSS requirements : 

## Injections
### SQL Injection
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | changed or unchanged | answer to the question "The assigned privileges to the vulnerable component"
Confidentiality | high | the goal of sql injection is to steal data (but the database could be empty or no values)
Integrity | low | even if the attacker can modify data this is not the main attack case
Availability | none | even if the attacker can shutdown the database the website is still available

### Remote Code Injection
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | changed or unchanged | answer to the question "The assigned privileges to the vulnerable component ?"
Confidentiality | high | 
Integrity | high | 
Availability | high | 

### Remote File Injection
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | high | 
Integrity | high |
Availability | none | 

### Local File Injection
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | changed or unchanged |  answer to the question "Scope of local file inclusion ?"
Confidentiality | low | 
Integrity | none |
Availability | none | 

### HTTP Response Manipulation
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | none | in general only the client is affected
Integrity | low | 
Availability | none | 

### Email injection
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | need user interaction and good phishing strategy
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | low | 
Availability | none | 


## Broken authentication and session management
### Authentication bypass
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | high | 
Integrity | high | 
Availability | low | 

### Privilege escalation
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | low | the attacker already had some privileges
Integrity | high | 
Availability | none | 

### Session fixation
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | the attacker needs to send the malicious session id to the victim
Scope | unchanged | 
Confidentiality | low | 
Integrity | low | 
Availability | none | 

### Failure to invalidate session
Parameter | Value | Comment
--- | --- | ---
Attack Vector | physical | most of the time invalidate session exploitation is when the victim is away from his computer and an attacker steal his session
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | because if the victim do actions on the websites in general the session is still valid
Scope | unchanged | 
Confidentiality | none | 
Integrity | low | 
Availability | none | 

### Concurrent logins
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | high | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | none | 
Availability | none | 


## Xml External Entities
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | high | but depends of the kind of xml injection (like sql injection)
Integrity | low | 
Availability | none | 

## CSRF
### Wide CSRF
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | low | 
Integrity | low | 
Availability | low | 

### On authenticated action
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | low | 
Integrity | low | 
Availability | none | 

### On anonymous action
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | low | 
Availability | none | 

### Logout action
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | none | 
Availability | none | 


## XSS
### Stocked XSS
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | changed | 
Confidentiality | none or low or high | answer to the question "impacted users by the xss?" (high = authenticated user with rights, low = authenticated user, none = others)
Integrity | low | 
Availability | none or low | answer to the question "impacted users by the xss?" (low = anonymous, none = others)

### Reflected XSS
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | changed |  
Confidentiality | none or low or high | answer to the question "impacted users by the xss?" (high = authenticated user with rights, low = authenticated user, none = others)
Integrity | low | 
Availability | none or low | answer to the question "impacted users by the xss?" (low = anonymous because a lot of users' browsers are impacted, none = others) 

### Self reflected XSS
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | changed | 
Confidentiality | none | the only impacted user is the attacker
Integrity | none | the only impacted user is the attacker
Availability | none | the only impacted user is the attacker


## Security Misconfiguration
### Unsafe cross origin resource sharing
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | high | 
Integrity | low | 
Availability | none | 

### Path traversal
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | high | 
Integrity | none | 
Availability | none | 

### Directory listing enabled
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | high | check if the informations listed are sensitives
Integrity | low | 
Availability |low | 

### Same site scripting
Parameter | Value | Comment
--- | --- | ---
Attack Vector | local | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | changed | 
Confidentiality | low | 
Integrity | low | 
Availability | none | 

### Using default credentials
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | none or low or high | answer to the question "impacted users by the xss?" (high = authenticated user with rights, low = authenticated user, none = others)
Integrity | none or low | answer to the question "impacted users by the xss?" (none = authenticated user, low = others)
Availability | none or low | answer to the question "impacted users by the xss?" (none = authenticated user, low = others)

### Potentially unsafe http method enabled
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | none | 
Availability | none | 

### Insecure ssl
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | high | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | Low | check the severity of ssl vulnerability
Integrity | none | 
Availability | none | 


## Sensitive data exposure
### Password disclosure
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | high | 
Integrity | high | 
Availability | low | 

### Private api keys
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | high | 
Integrity | high | 
Availability | low | 

### User enumeration
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low or high | answer to the question "type of enumeration ?"
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | low | 
Integrity | none | 
Availability |none | 

### Visible detailed error page
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | none | 
Availability | none | 

### token in url
Parameter | Value | Comment
--- | --- | ---
Attack Vector | physical | need access to the log where urls are recorded
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | low or none | 
Integrity | low or none | answer to the question "Type of token ?"
Availability | none | 

### Internal ip disclosure
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged | 
Confidentiality | none or low |  answer to the question "Type of ip address ?"
Integrity | none | 
Availability | none | 

### Internal hostname disclosure
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | none | 
Scope | unchanged or changed | if enumeration it's changed
Confidentiality | none or low |  answer to the question "Type of hostname ?"
Integrity | none | 
Availability | none | 


## Unvalidated Redirects and Forwards
### Open Redirect GET
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | low | 
Availability | none | 

### Open Redirect POST
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | none | 
Availability | none | 

### Open Redirect HEADERS
Parameter | Value | Comment
--- | --- | ---
Attack Vector | network | 
Attack Complexity | low | 
Privileges Required | none or low or high | answer to the question "privileges required ?"
User Interaction | required | 
Scope | unchanged | 
Confidentiality | none | 
Integrity | none | 
Availability |none | 
