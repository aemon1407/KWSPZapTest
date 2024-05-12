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
|Aiman Fathi Bin Mohd Fairuz |Identify, Evaluate and Prevent the alert of Server OS and Server-Side Scripting, Hash Disclosure, CSRF |
|Safwan Bin Roslin           |Identify, Evaluate and Prevent the alert of JS Library, Cookie Poisoning, Potential XSS, Information Disclosure |
|Muhammad Haniff bin Ismail  |Identify, Evaluate and Prevent the alert of Secured Cookie, CSP, HTTPS Implementation(TLS/SSL) |

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

1. ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/3d8a97a3-2f43-4eb7-8c42-4da51498509a)
2. ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/2724d4ea-b5de-4728-9b70-967ab61fc59f)
3. ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/69ce572c-3c84-4950-abb4-ec3c7fc8c3b7)
4. ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/ac794df0-b8ad-42cd-a520-acee8b0e53a0)
5. ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/7873b92e-a815-4e63-bb43-afe03c3b5bd6)
6. ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/0f06439d-f781-4598-9673-4d4339c3b38d)


## List of Tables

## References
1. https://www.kwsp.gov.my/ms/ahli/gambaran-keseluruhan
2. https://openwall.info/wiki/john/sample-hashes
3. https://turingsecure.com/knowledge-base/issues/password-hash-disclosure/#:~:text=Description,guess%20the%20plain%20text%20password.
4. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
5. https://cwe.mitre.org/data/definitions/352.html
   
## <a name="desc"/> Brief Description 
www.kwsp.gov.my is a government agency responsible for managing retirement savings plans for private sector workers in Malaysia. Members can also check for their EPF account balance, review their contribution history, update personal details and download forms for various transactions. The site also gives information on EPF policies, investment options and retirement planning resources. In general www.kwsp.gov.my is a vital tool in facilitating communication between the organization and its members, providing them with retirement savings information and services that are clear as well as reachable.

Due to its nature of handling fund, withdrawal request and storing Malaysian's data, it is important for KWSP to have a strong and trusted security to prevent any unwanted issues such as data breached, unauthorized withdrawal etc. Therefore, our case study purpose is to do security testing using OWASP ZAP on www.kwsp.gov.my to see if the website is secure and identify any potential risks.

## <a name="reslt"/> Result of Testing
### <a name="server"/> a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.
#### Identify Vulnerabilities
- This alert is not detected in www.kwsp.gov.my website using manual scan. 
#### Evaluate Vulnerabilities
- The kind of alert is not detected by the ZAP.
#### Prevention Vulnerabilities
- The kind of alert is not detected by the ZAP.
  
### <a name="hash"/> b. Hash Disclosure
![Hash](https://github.com/aemon1407/KWSPZapTest/assets/128023708/54451d83-9a1e-4d9c-bc85-e4ac25576663)
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
![CSRF](https://github.com/aemon1407/KWSPZapTest/assets/128023708/e5c0f71b-4f8d-4f15-b0ff-3320f194c223)
#### Identify Vulnerabilities
Absence of Anti-CSRF Tokens
- Risk Level: Medium
- Confidence Level: Low
- CWE ID: 352 (Cross-Site Request Forgery)
#### Evaluate Vulnerabilities
- No Anti-CSRF tokens were found in a HTML submission form.
A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.

CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
    * The victim is on the same local network as the target site.

CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.

#### Prevent Vulnerables
Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
For example, use anti-CSRF packages such as the OWASP CSRFGuard.

Phase: Implementation
Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.

Phase: Architecture and Design
Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
Note that this can be bypassed using XSS.

Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.
Note that this can be bypassed using XSS.

Use the ESAPI Session Management control.
This control includes a component for CSRF.

Do not use the GET method for any request that triggers a state change.

Phase: Implementation
Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.

### <a name="seccoo"/> d. Secured Cookies
 #### Identify Vulnerabilities
  1. Secured Cookies - Cookie No HttpOnly Flag
   - Risk Level: Low
   - Confidence Level: Medium
   - Evidence: Set-Cookie: test_cookie
   - CWE ID: 1004
   - WASC ID: 13

  2. Secured Cookies - Cookie Without Secure Flag
   - Risk Level: Low
   - Confidence Level: Medium
   - Evidence: Set-Cookie: __cflb
   - CWE ID: 614
   - WASC ID: 13

  3. Secured Cookies - Cookie with SameSite Attribute None
   - Risk Level: Low
   - Confidence Level: Medium
   - Evidence: Set-Cookie: __cf_bm
   - CWE ID: 1275
   - WASC ID: 13

  4. Secured Cookies - Cookie without SameSite Attribute
   - Risk Level: Low
   - Confidence Level: Medium
   - Evidence: Set-Cookie: myepfcookie
   - CWE ID: 1275
   - WASC ID: 13

 #### Evaluate Vulnerabilities
  1. Secured Cookies - Cookie No HttpOnly Flag
   - The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.
   - The HttpOnly flag directs compatible browsers to prevent client-side script from accessing cookies. Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate the risk associated with Cross-Site Scripting (XSS) where an attacker's script code might attempt to read the contents of a cookie and exfiltrate information obtained. When set, browsers that support the flag will not reveal the contents of the cookie to a third party via client-side script executed via XSS.

  Related:
   - CVE-2022-24045: Web application for a room automation system has client-side Javascript that sets a sensitive cookie without the HTTPOnly security attribute, allowing the cookie to be accessed.
   - CVE-2014-3852: CMS written in Python does not include the HTTPOnly flag in a Set-Cookie header, allowing remote attackers to obtain potentially sensitive information via script access to this cookie.
   - CVE-2015-4138: Appliance for managing encrypted communications does not use HttpOnly flag.

  2. Secured Cookies - Cookie Without Secure Flag
   - The Secure attribute for sensitive cookies in HTTPS sessions is not set, which could cause the user agent to send those cookies in plaintext over an HTTP session.

  Related:
   - CVE-2004-0462: A product does not set the Secure attribute for sensitive cookies in HTTPS sessions, which could cause the user agent to send those cookies in plaintext over an HTTP session with the product.
   - CVE-2008-3663: A product does not set the secure flag for the session cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie.
   - CVE-2008-3662: A product does not set the secure flag for the session cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie.
   - CVE-2008-0128: A product does not set the secure flag for a cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie.

  3. Secured Cookies - Cookie with SameSite Attribute None
   - The SameSite attribute for sensitive cookies is not set, or an insecure value is used.
   - The SameSite attribute controls how cookies are sent for cross-domain requests. This attribute may have three values: 'Lax', 'Strict', or 'None'. If the 'None' value is used, a website may create a cross-domain POST HTTP request to another website, and the browser automatically adds cookies to this request. This may lead to Cross-Site-Request-Forgery (CSRF) attacks if there are no additional protections in place (such as Anti-CSRF tokens).

  4. Secured Cookies - Cookie without SameSite Attribute
   - Cookie Without SameSite Attribute can lead to a Cross-site Request Forgery (CSRF) attack.

   - “SameSite” attribute allows to declare whether the cookie should be restricted to a first-party or same-site context. Meaning that all the cookies without the “SameSite” attribute would be added to any requests initiated to any other website. This allows attackers to abuse sessions belonging to an authorized user. This browser behavior can also be misused for other purposes like tracking users or advertising.

 #### Prevention Vulnerabilities
  1. Secured Cookies - Cookie No HttpOnly Flag
   - Leverage the HttpOnly flag when setting a sensitive cookie in a response.

  2. Secured Cookies - Cookie Without Secure Flag
   - Always set the secure attribute when the cookie should sent via HTTPS only.

  3. Secured Cookies - Cookie with SameSite Attribute None
   - Set the SameSite attribute of a sensitive cookie to 'Lax' or 'Strict'. This instructs the browser to apply this cookie only to same-domain requests, which provides a good Defense in Depth against CSRF attacks. When the 'Lax' value is in use, cookies are also sent for top-level cross-domain navigation via HTTP GET, HEAD, OPTIONS, and TRACE methods, but not for other HTTP methods that are more like to cause side-effects of state mutation.

  4. Secured Cookies - Cookie without SameSite Attribute
   - instruct browsers to control if cookies should be sent along with requests initiated by third-party websites. “SameSite” attribute on a cookie provides three ways to control its behavior:

      - Lax - Cookies are allowed to be sent along with top-level navigations. This is the default value in modern browsers.
      - Strict - Cookies will be sent only in a first-party context.
      - None - Cookies will be sent in all contexts. None requires the “Secure” attribute in latest browser versions.

  References:
   - https://cwe.mitre.org/data/definitions/1004.html
   - https://cwe.mitre.org/data/definitions/614.html
   - https://cwe.mitre.org/data/definitions/1275.html
   - https://scanrepeat.com/web-security-knowledge-base/cookie-without-samesite-attribute#:~:text=%E2%80%9CSameSite%E2%80%9D%20attribute%20allows%20to%20declare,belonging%20to%20an%20authorized%20user.

### <a name="csp"/> e. CSP
 #### Identify Vulnerabilities
   - Identified as: Wildcard Directive
   - Risk Level: Medium
   - Confidence Level: High
   - CWE ID: 693
   - WASC ID: 15

 #### Evaluate Vulnerabilities
   - Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
   - Other Info: The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: 
script-src, style-src, img-src, connect-src, frame-ancestors, font-src, media-src, object-src, manifest-src, worker-src, form-action

     The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.
   

 #### Prevention Vulnerabilities
   - Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.
   - Specify content sources individually and use specific directives to control content sources. This helps ensure that only trusted and authorized sources are allowed, reducing the risk of potential security vulnerabilities.

 References:
 - https://www.w3.org/TR/CSP/
 - https://caniuse.com/#search=content+security+policy
 - https://content-security-policy.com/

### <a name="jsl"/> f. JS Library
 #### Identify Vulnerabilities
  - Identified as: Vulnerable JS Library
  - Risk Identified: Medium
  - ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/3d8a97a3-2f43-4eb7-8c42-4da51498509a)
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
 #### Identify Vulnerabilities
  - There is no alert found on OWASP ZAP and no risk level and CWE ID can be identified.

 #### Evaluate Vulnerabilities
  - Not available since there is https implementation for this website that can be seen at the URL of the website.

 #### Prevention Vulnerabilities
  - 

### <a name="cookie"/> h. Cookie Poisoning
 #### Identify Vulnerabilities
  - Identified as: Loosely Scoped Cookie
  - ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/2724d4ea-b5de-4728-9b70-967ab61fc59f)
  - Risk Level: Informational
  - Confidence Level: Low
  - CWE ID: 565
  - WASC ID: 15
    
 #### Evaluate Vulnerabilities
  This is called a cookie poisoning attack, and becomes exploitable when an attacker can manipulate the cookie in various ways. In some cases this will not be exploitable, however, allowing URL parameters to set cookie values is generally considered a bug. Cookies can be scoped by domain or path. This check is only concerned with domain scope.The domain scope applied to a cookie determines which domains can access it. For example, a cookie can be scoped strictly to a subdomain e.g. www.nottrusted.com, or loosely scoped to a parent domain e.g. nottrusted.com. In the latter case, any subdomain of nottrusted.com can access the cookie. Loosely scoped cookies are common in mega-applications like google.com and live.com. Cookies set from a subdomain like app.foo.bar are transmitted only to that domain by the browser. However, cookies scoped to a parent-level domain may be transmitted to the parent, or any subdomain of the parent.
    
 #### Prevent Vulnerabilities
 Do not allow user input to control cookie names and values. If some query string parameters must be set in cookie values, be sure to filter out semicolon's that can serve as name/value pair delimiters.

 Reference: [https://cwe.mitre.org/data/definitions/1275.html](https://www.zaproxy.org/docs/alerts/10029/)
 
### <a name="xss"/> i. Potential XSS
 #### Identify Vulnerabilities
 There is no alert found on OWASP ZAP and no risk level and CWE ID can be identified.
 
 #### Evaluate Vulnerabilities
 Not available since there is https implementation for this website that can be seen at the URL of the website.
 
 #### Prevent Vulnerabilities
 Not available for the website. However, the solution for this type of alert is to validate all input and sanitize output it before writing to any HTML attributes.
 
### <a name="info"/> j. Information Disclosure
 #### Identify Vulnerabilities
 
  1. Information Disclosure - Sensitive Information in URL
     - ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/69ce572c-3c84-4950-abb4-ec3c7fc8c3b7)
     - Risk Level: Informational
     - Confidence Level: Medium
     - Evidence: com_liferay_product_navigation_user_personal_bar_web_portlet_ProductNavigationUserPersonalBarPortlet:/o/com.liferay.product.navigation.user.personal.bar.web/css/main.css
     - CWE ID: 200
     - WASC: 13
       
  2. Information Disclosure - Suspicious Comments
     - ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/ac794df0-b8ad-42cd-a520-acee8b0e53a0)
     - Risk Level: Informational
     - Confidence Level: Low
     - Evidence: from
     - CWE ID: 200
     - WASC: 13
       
 #### Evaluate Vulnerabilities

   1. Information Disclosure - Sensitive Information in URL
      - The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment
      - Other Info 
      ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/7873b92e-a815-4e63-bb43-afe03c3b5bd6)

  2. Information Disclosure - Suspicious Comments
     - The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.
     - Other Info
       ![image](https://github.com/aemon1407/KWSPZapTest/assets/106056077/0f06439d-f781-4598-9673-4d4339c3b38d)

  **CWE-200** stands for "Exposure of Sensitive Information to an Unauthorized Actor". It's a general classification in the Common Weakness Enumeration (CWE) list  used for software security concerns. Information exposure can have serious consequences.  If personal information (like financial data or health records) is leaked, it can damage a person's reputation or even lead to identity theft. For businesses, it can cause financial losses and reputational harm.

 #### Prevent Vulnerabilities

   1. Information Disclosure - Sensitive Information in URL
       - Do not pass sensitive information in URLs.

   2. Information Disclosure - Suspicious Comments
       - Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.
 



