# Case Study 1: www.kwsp.gov.my
## Group Name
Razer
## Group Member
|Member                      |Matric ID|
|----------------------------|---------|
|Aiman Fathi Bin Mohd Fairuz |2121549  |
|Safwan                      |2113779  |
|Ahli 3                      |121244   |
## Assigned Task
|Member       |Appointed Task          |
|-------------|------------------------|
|Aiman Fathi  |Identify Vulnerabilities|
|Safwan       |Evaluate Vulnerabilities|
|Ahli 3       |Prevent Vulnerabilities |

## Table of Content

## List of Figures

## List of Tables

## References
1. https://www.kwsp.gov.my/ms/ahli/gambaran-keseluruhan
2. 
## Brief Description 
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

## Result of Testing
### a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.
#### Identify Vulnerabilities
- This alert is not detected in www.kwsp.gov.my website using manual scan. Therefore, the risk level is not available.
#### Evaluate Vulnerabilities
- The kind of alert is not detected by the ZAP, therefore, no need to evaluate the alert.
#### Prevention Vulnerabilities

### Hash Disclosure
#### Identify Vulnerabilities
##### Hash Disclosure - MD5 Crypt
- A hash was disclosed by the web server
- CWE ID: 200 - The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- Risk Level: High
##### Hash Disclosure - SHA256 Crypt
- A hash was disclosed by the web server. - SHA-256 Crypt
- CWE ID: 200 - The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- Risk Level: High
#### Evaluate Vulnerabilities
- MD5 Crypt
- 

#### Prevention Vulnerabilities
MD5 Crypt
- 

### CSRF
#### Identify Vulnerabilities

#### Evaluate Vulnerabilities

#### Prevention Vulnerabilities

### Secured Cookies

### CSP

### JS Library

### HTTPS Implementation (TLS/SSL)

### Cookie Poisoning

### Potential XSS

### Information Disclosure



