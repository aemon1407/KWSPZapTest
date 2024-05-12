# Case Study 1: www.kwsp.gov.my
## Group Name
Razer
## Group Member
|Member                      |Matric ID|
|----------------------------|---------|
|Aiman Fathi Bin Mohd Fairuz |2121549  |
|Safwan                      |2113779  |
|Muhammad Haniff bin Ismail  |2110619  |
## Assigned Task
|Member       |Appointed Task          |
|-------------|------------------------|
|Aiman Fathi  |Identify Vulnerabilities|
|Safwan       |Evaluate Vulnerabilities|
|Haniff       |Prevent Vulnerabilities |

## Table of Content
1. [Brief Description](#desc)
2. [Result of Testing](#reslt)
   1. [Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.](#server)
   2. [Hash Disclosure](#hash)
   3. [CSRF](#csrf)
   4. [Secured Cookies](#seccoo)
   5. [CSP](#csp)
   6. [JS Library](#jsl)
   7. [HTTPS Implementation (TLS/SSL)](#https)
   8. [Cookie Poisoning](#cookie)
   9. [Potential XSS](#xss)
   10. [Information Disclosure](#info)

## List of Figures

## List of Tables

## References
1. https://www.kwsp.gov.my/ms/ahli/gambaran-keseluruhan
2. https://openwall.info/wiki/john/sample-hashes
3. https://turingsecure.com/knowledge-base/issues/password-hash-disclosure/#:~:text=Description,guess%20the%20plain%20text%20password.
## <a name="desc"/> Brief Description 
www.kwsp.gov.my is a government agency responsible for managing retirement savings plans for private sector workers in Malaysia. Members can also check for their EPF account balance, review their contribution history, update personal details and download forms for various transactions. The site also gives information on EPF policies, investment options and retirement planning resources. In general www.kwsp.gov.my is a vital tool in facilitating communication between the organization and its members, providing them with retirement savings information and services that are clear as well as reachable.

Due to its nature of handling fund, withdrawal request and storing Malaysian's data, it is important for KWSP to have a strong and trusted security to prevent any unwanted issues such as data breached, unauthorized withdrawal etc. Therefore, our case study purpose is to do security testing using OWASP ZAP on www.kwsp.gov.my to see if the website is secure and identify any potential risks.


|Alert                                        |Alert Stage|
|---------------------------------------------|-----------|
|Hash Disclosure - MD5 Crypt                  |High       |
|Hash Disclosure - MSha256 Crypt              |High       |
|SQL Injection - Oracle - Time Based          |High       |
|CSP: Wildcard Directive                      |Medium     |
|CSP: Script-src unsafe inline                |Medium     |
|CSP: Style-src unsafe inline                 |Medium     |
|CSP: Header not set                          |Medium     |
|Information Disclosure - Suspicious Comment  |Medium     |

## <a name="reslt"/> Result of Testing
### <a name="server"/> a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.
#### Identify Vulnerabilities
- This alert is not detected in www.kwsp.gov.my website using manual scan. Therefore, the risk level is not available.
#### Evaluate Vulnerabilities
- The kind of alert is not detected by the ZAP, therefore, no need to evaluate the alert.
#### Prevention Vulnerabilities

### <a name="hash"/> b. Hash Disclosure
#### Identify Vulnerabilities
Hash Disclosure - MD5 Crypt
- A hash was disclosed by the web server
- CWE ID: 200 - The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- Risk Level: High
  
Hash Disclosure - SHA256 Crypt
- A hash was disclosed by the web server. - SHA-256 Crypt
- CWE ID: 200 - The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- Risk Level: High
  
#### Evaluate Vulnerabilities
MD5 Crypt
- The hashed data was exposed to someone who shouldn't have access to it. This could be due to a misconfiguration, a vulnerability in the web server or application, or some other security issue.
-  The alert indicates a potential security vulnerability where hashed data, possibly containing sensitive information, was inadvertently disclosed by the web server. This could lead to security risks if the disclosed hashes are used maliciously to reverse-engineer the original sensitive data, such as passwords.

SHA256 Crypt
- The alert for SHA256 is the same as MD5 Crypt, it could potentially be reversed to reveal the original sensitive information. However, due to the stronger cryptographic properties of SHA-256, it would be significantly harder to reverse or brute-force the hash to retrieve the original data.
-  Just like MD5 Crypt, it indicates a potential security vulnerability where hashed data, possibly containing sensitive information, was inadvertently disclosed by the web server. This could lead to security risks if the disclosed hashes are used maliciously to reverse-engineer the original sensitive data, such as passwords.

#### Prevention Vulnerabilities
MD5 Crypt & SHA256
- Ensure that hashes that are used to protect credentials or other resources are not leaked by the web server or database. There is typically no requirement for password hashes to be accessible to the web browser.
- Another way to prevent this vulnerabilities is to hash the passwords at all times and arrow a solid schema i.e. BCrypt, SHA-256, or PBKDF2. Also to make it difficult to decrypt one should hash passwords with a unique salt. Moreover among other things including rate limiting administrators are advised to takes steps to secure against brute force attacks.

### <a name="csrf"/> c. CSRF
#### Identify Vulnerabilities
- This alert is not detected in www.kwsp.gov.my website using manual scan. Therefore, the risk level is not available.
#### Evaluate Vulnerabilities
- The kind of alert is not detected by the ZAP, therefore, no need to evaluate the alert.
#### Prevention Vulnerabilities

### <a name="seccoo"/> d. Secured Cookies

### <a name="csp"/> e. CSP

### <a name="jsl"/> f. JS Library

### <a name="https"/> g. HTTPS Implementation (TLS/SSL)

### <a name="cookie"/> h. Cookie Poisoning

### <a name="xss"/> i. Potential XSS

### <a name="info"/> j. Information Disclosure



