# Case Study 1: www.kwsp.gov.my
## Group Name
Razer
## Group Member
|Member                      |Matric ID|
|----------------------------|---------|
|Aiman Fathi Bin Mohd Fairuz |2121549  |
|Safwan Bin Roslin           |2113779  |
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
 #### Identify Vulnerabilities
  - Risk Identified: Medium
  - Confidence Level: Low
  - Evidence: * Bootstrap v3.3.7
  - CWE ID: 829

 #### Evaluate Vulnerabilities
  - CWE-829 refers to the "Inclusion of Functionality from Untrusted Control Sphere" vulnerability. This CWE typically applies to situations where a software component or library includes functionality from a source that is not fully trusted or from an untrusted control sphere. In the context of JavaScript libraries, CWE-829 can manifest when a library incorporates code or features from sources that are not verified or could potentially be compromised.
    
  - Related:
    - **CVE-2018-14041**: This CVE refers to a vulnerability in the Linux kernel's 802.11 subsystem. It could allow an attacker within range to cause a denial of service (DoS) or potentially execute arbitrary code.
    - **CVE-2019-8331**: This CVE pertains to a vulnerability in the TYPO3 extension "rte_ckeditor." It allows remote attackers to conduct cross-site scripting (XSS) attacks via a crafted URL.
    - **CVE-2018-20677**: This CVE involves a vulnerability in the node-forge npm package before version 0.7.5. It allows remote attackers to conduct XML External Entity (XXE) attacks via a crafted XML document.
    - **CVE-2018-20676**: Similar to CVE-2018-20677, this CVE involves a vulnerability in the node-forge npm package before version 0.7.5. It allows remote attackers to conduct XML External Entity (XXE) attacks via a crafted XML document.
    - **CVE-2018-14042**: This CVE is also related to the Linux kernel's 802.11 subsystem. It allows attackers within range to cause a denial of service (DoS) or potentially execute arbitrary code.
    - **CVE-2016-10735**: This CVE is associated with a vulnerability in the Linux kernel's packet socket implementation. It allows local users to cause a denial of service (crash) or possibly gain privileges via crafted system calls.

  #### Prevention of Vulnerabilities
   - To mitigate CWE-829, it's important for developers to carefully vet and validate the sources of external code included in their libraries, ensuring that only trusted and verified components are used to minimize the risk of including potentially harmful or malicious functionality.
   - Keeping libraries and dependencies up to date with security patches and using static analysis tools to scan for vulnerabilities can help identify and address such risks.

References:
- https://nvd.nist.gov/vuln/detail/CVE-2018-14041
- https://nvd.nist.gov/vuln/detail/CVE-2019-8331
- https://nvd.nist.gov/vuln/detail/CVE-2018-20677
- https://nvd.nist.gov/vuln/detail/CVE-2018-20676
- https://nvd.nist.gov/vuln/detail/CVE-2018-14042
- https://nvd.nist.gov/vuln/detail/CVE-2016-10735
- https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- https://cwe.mitre.org/data/definitions/829.html

### <a name="https"/> g. HTTPS Implementation (TLS/SSL)

### <a name="cookie"/> h. Cookie Poisoning
 #### Identify Vulnerabilities
  - Risk Level: Low
  - Confidence Level: Medium
  - Set-Cookie: __cflb
  - CWE ID: 1275
  - WASC ID: 13
    
 #### Evaluate Vulnerabilities
  - A cookie has been set with its SameSite attribute set to "none", which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.
    
  - There are two main ways CWE-1275 can manifest:
    - Missing SameSite Attribute: The cookie doesn't have the SameSite attribute set at all. This means the browser might include the cookie with requests from any website, including potentially malicious ones.
    - Incorrect SameSite Attribute Value: The cookie has the SameSite attribute set to a value that weakens the protection against CSRF attacks. For example, setting it to 'None' allows the browser to include the cookie with cross-site requests.
    
 #### Prevent Vulnerabilities
  - Set the SameSite attribute to 'Strict' on all sensitive cookies. This ensures that the browser won't include the cookie with requests from other websites, significantly reducing the risk of CSRF attacks.
 
### <a name="xss"/> i. Potential XSS

### <a name="info"/> j. Information Disclosure



