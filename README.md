# DevSecOps Bootcamp

## Security Essentials

- Government regulations:
  - GDPR: General Data Protection Regulation - EU's data protection law
- Compliance:
  - Regulations must be enforced. Audits are done to make sure the regulations are followed
- __Types of Attacks:__
  - _Phishing attack/Social Hacking:_
    - Tricking a human, instead of a system
    - e.g. Attacker sends a legitimate looking email that executes a harmful script when clicked on by the user
      - phone call, misrepresenting a person with a fake ID card, thumbdrive from a co-worker or found in the parking lot, getting forwarded to an identical but fake website from the original authentic website, ...etc
  - _Cross Site Scripting (XSS):_
    - Takes advantage of application vulnerabilities
    - Attacker injects the website with malicious script which is then loaded and executed in a user's browser
    - Common impact: stealing user identity
  - _Client Side Request Forgery (CSRF)/Session Hijacking:_
    - <https://owasp.org/www-community/attacks/csrf>
    - Attacker forges a request by pretending to be another user
    - "Client-side" indicates that the attack takes place on the user's side, within their browser
    - CSRF is an attack that tricks the victim into submitting a malicious request. It inherits the identity and privileges of the victim to perform an undesired function on the victim’s behalf.
    - If the application does not have a proper logic for revoking stolen Session IDs and tokens, an attacker can hold on to those keys and gain access for as long as they like
    - An attacker can use XSS to inject JS code that steals session onformation and start making those forged requests as the authorized user within that application using that logged in user's session
    - This can happen if the application has weak authentication checks, does not reject eternal code, e.g. JS code, does not properly validate user on email change
  - _Server- Side Request Forgery (SSRF):_
    - Attackers forges the request pretending to be the server
    - <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery>
    - In a Server-Side Request Forgery (SSRF) attack, the attacker can abuse functionality on the server to read or update internal resources. The attacker can supply or modify a URL which the code running on the server will read or submit data to, and by carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like http enabled databases or perform post requests towards internal services which are not intended to be exposed.
    - Requires more in-depth knowledge of the application's architecture and behavior, but more dangerous because of administrative access and access to all user data
  - _SQL Injection:_
    - Attacker manipulates or injects malicious SQL code into a database query
    - Takes advantage of improper handling of user input in an app that interacts with a DB
    - Dangerous because the attacker may get access to all the data, delete all the data or manipulate the data
  - _Third-Party Libraries:_
    - If a vendor does not have proper security, it also exposes all the companies that are using it to vulnerabilities
    - This then exposes your company's users to the vulnerability, there by cascading the attack not just to the vendor but to your company and to your users
    - If a third-party library has a security hole, then that becomes your security deficiency, therefore you need to validate the libraries and vendors used in your applications and resources
    - Common sources:
      - Security risks introduced by developers
      - Small non-offical libraries with intentional malicious code
    - Keep track of vulnerabilities discovered from the libraries used in your apps and upgrade to the versions with fixed patches
    - Public databases for known security vulnerabilities:
      - CVE: Common Vulnerabilities and Exposures
        - This is a system that provides a reference for publicly known security vulnerabilities
    - PII: Personal Identifiable Information: Information that, when used alone or with other relevant data can identify an individual; like: biometric identifiers, name, full face photos, geographical info, phone, acocunt numbers, address, vehical or insurance, birthdate, medical and health plan info, email, SSN etc. This information is unique to a user
  - _Weak Password:_
    - Attackers can use brute-force attacks through use of trial and error to try and break into a network or website. They typically use hacking tools to automate these login attempts
    - Enforce strong password policy: e.g. specific number of characters, special characters, forbid phrase passwords, do not reuse the same password for multiple applications, use password managers like lastPass or 1pass.
      - Password managers help with managing hundreds of passwords. The only password you need to remember is a strong master password to lastPass
  - _Denial of Service Attack (DOS):_
    - Target system is flooded with an overwhelming volume of traffic
    - Distributed Denial of Service (DDoS): Often multiple compromised systems (botnet) are coordinated to launch the attack simultaneously
    - Attack consumes all the available bandwidth, consumes too many connections and exhausts the server's resources, such as CPU, memory..., leaving the server unable to handle legitimate requests
    - How to defend against: Firewalls, Intrusion Detections Systems (IDS), Traffic filtering, etc.
- __Open Web Application Security Project (OWASP) Top 10 Project__
  - <https://owasp.org/www-project-top-ten/>
  - It is a global non-profit organization that is focussed on improving the security of web applications
  - Lists the most critical web application security risks (list of common threats).
  - Regularly updated (every 3-4 yrs) to reflect emerging threats
  - This list contains high level categorization of the threats
  - Lists with more detailed security threats: Common Weakness Enumeration (CWE), OWASP ASVS
  - The order of the list reflects the combination of several factors, including:
    - Incident Rate (likelihood)
    - Impact
    - Exploitability
    - Detectability
  - The more comprehensive OWASP is: OWASP Application Security Verification Standard(ASVS): <https://owasp.org/www-project-application-security-verification-standard/>
  - _8 of the categories are from data:_
    - Data factors: CWEs Mapped, Incidence Rate, Weighted Exploit, Weighted Impact, Total Occurrences, ...
  - _2 categories are from Top 10 community survey:_
    - There are some security risks and trends that aren't in the data
    - It also takes time to develop new testing methodologies for new vulnerability types, etc.
    - It allows for security practitioners to vote for what they see as the highest risks that might not be in the data (yet)
  1. _Broken Access Control_ 
    - Vulnerabilities in the app to properly control user's permission
      - Encompasses the application not being able to control who has access to what application resources: by-passing authorization safeguards, becoming priviledges users
      - Access control: ensuring only authorized users are granted the permissions to access specific resources or perform certain actions
      - Phishing attacks, session hijaking(CSRF) are part of this category
    - It also includes when an application accidentally exposes sensitive information to unauthorized users. 
      - e.g. when the requests are based on the URL and the request data is part of the URL itself, hackers can manipulate that URL and execute a request that gives them access to some unauthorized data, like files on the server ...
    - So basically whenever an application fails to detect a request forgery, not detecting that it's returning data that it should not be exposing to an unauthorized user, or allowing a hacker to impersonate a legitimate user or give them unauthorized access to some resources, this allows for broken access control vulnerabilities
  2. _Cryptographic Failures (lack or Weak cryptography)_
    - This category is about weak encryption of data.
      - Weak encryption (use of broken or risky/weak crypto algorithm)
      - Hard coded credentials (Passwords, API keys, ...)
      - Use of insecure protocols like HTTP
        - Data needs to be protected both at rest and in transit
        - Protocols are used to transmit data in a network and HTTP requests and responses are not encrypted, making the data accessible to monitoring the session
    - Previously known as "Sensitive Data Exposure" because this is more of a symptom while the actual root cause is crytpographic failure
  3. _Injection_
     - This includes any type of injection that the hacker can execute in an application
      - 2 common types of injection:
       - XSS, SQL injection
     - Application allows hackers to inject malicious code
     - Template injection examples:
      - Templates: e.g Jinja2, JSP, Mustache, Handlebars, etc
      - Using malicious temolate directives, an attacker may be able to execute arbitrary code before it is processed then they can invoke any expression they want, potentially taking full control of the web server
     - Injections can be server-side or client-side
     - Fix:
      - Write code in a way that always validates and sanitizes user input
      - Avoid creating templates from user input.
       - Expect malicious user input by default
  4. _Insecure Design_
    - Focuses on risks to design and architectural flaws
    - It deals more with designing and conceptualizing security in applications and not the implementation side of it
      - Doing an audit of the app to see what threats it can be exposed to
      - This is known as _threat modelling_, which is the process used to identify, assess and mitigate potential threats in a system or application before it is even released.
      - Promotes a security mindset thoughout the development lifecycle, helping to create more robust and resilient systems
  5. _Security Misconfiguration_
    - These flaws can be introduced during the configuration of the application or its underlying environment
    - Can happen at any layer of the application stack:
      - Within the application config, network config, storage, etc.
    - Risk of misconfigurations increases with complex systems, and high number of services
      - Examples:
        - Improper access configuration, unneccessary open ports, SSH allowing access from any source
        - Unnecessary services running
        - Logs configured in a way that they are leaking data, e.g. error handling messages revealing important information
        - Unnecessary features enabled
        - Using default accounts and passwords from third-party services like databases or message brokers
        - Public access to a storage bucket with sensitive data when it should be private
  6. _Vulnerable and Outdates Components_
    - Focuses on third-party dependencies of your application as well as third-party services that might be exposed to vulneabilities
      - They typically run with the same privileges as the app itself, thereby the exposure to affect the whole system
  7. _Identification and Authentication Failures_
    - Deals with failure to properly identify and authenticate a user
    - Previously known as "Broken Authentication"
    - Includes vulnerabilities that are specifically related to identification
      - Identification: The act of identifyong a particular user (often through a username) or other credentials and the authentication process of validating that a suer is whi they calim to be (proof of user's identity)
      - Authentication is different from authorization.
        - Authorization: process of validatiing that the user (who has previously authenticated) has the permission to perform a particular action
    - Causes:
      - Weak confirmation of user identity
      - Permitting default, weak or well-known passwords
        - Prevent by implementing weak password checks
      - Missing or ineffective MFA which fails to defend against automated credential stuffing, brute force and stolen credential reuse attacks
        - Username and Password is not enough
        - MFA requires users to provide multiple forms of evidence to verify their identity
        - MFA: Something you own, know, possess
      - Weak Credential recovery and forgotten password processes
      - Using plain text or weakly hashed passwords (relates to cryptographic failures)
      - User sessions and authentication tokens are not properly validated
        - Session ID issued and saved in browser to identify user throughout the session, instead of sending login credentials for every request
        - Session ID needs to be validated when the user logs out
        - The app needs to be able to track user inactivity so that it can delete user session or automatically log user out after a specific time of inactivity
        - There are many standardized frameworks that help manage the authentication part of the app. 
          - Recommended because library maintainers have more expertise in handling secure authentication
  8. _Software and Data Integrity Failures_
    - Failures related to code and infrastructure that do not protect against integrity violations 
      - e.g. usage of code, libraries and plugins from non-validated sources, repositories or CDNs
        - Deals more with the source of the component
      - auto-updates downloading without integrity verification
  9.  _Security Logging and Monitoring Failures_
    - Usually hackers do not suceed on first try. Usually multiple actuons are needed to hack into a system and gain access to sensitive data. With proper monitoring and alerting system, you should notice the attempts
    - Without logging, monitoring and alerting, breaches cannot be detected. This also means that you will not be able to trace and analyze to improve security
      - Logging (information collection): Capturing and storing information about the behavior of an application system
        - records events, actions and errors
      - Monitoring: real-time observation of the logs, monitoring and analyzing metrics
        - Detect suspicious behavior, assess system health, performance, availability
        - Monitoring systems continuously evaluate data against predefines rules or thresholds and if a metric exceeds or falls below the specified threshold, an alert is triggered
        - Logging, monitoring and alerting are essential components
    - Configure logging for apps and thrid party components that are security relevant
      - Important auditable events like logins, failed logins, high value transactions
      - Ensure sufficient user context is logged to identify suspicious or malicious accounts
  10. _Server-Side Request Forgery (SSRF)_
  - Occurs when a web app allows an atacker to coerce the app to send a request to a remote source and then web app fetches a remote resource without validating the user-supplied URL
    - Servers have more priviledges than the client.
    - Attackercs can use SSRF to attack systems that are protected behind web application firewalls, VPN or network access control lists
      - They can do port scans on internal servers for security holes like open ports with a HTTP request and SSRF payload
      - Access local files or internal services to gain sensitive information
      - access metadata storage. Most cloud providers have metadata storage, which an attacker can read to gain sensitive information
- __Security in Layers__
  - Security is layered
  - That way, attackers have to work on different layers to get to your data, resources and applications
  - e.g. firewalls, ports, access controls, monitoring and alerting...
    - Principle of least privilege: limits access for employees and internal services
      - Users, process and systems are only granted the minimum privileges necessary to perform the tasks. This limits the damage done through permissions
  - DevSecOps works to automate checking (security testing, vulnerability scanning, code analysis, compliance checks ...) and validating that all layers of security are implemented and in place, giving you a visibility of how secure your systems are/what the security posture looks like

## Introduction to DevSecOps

- __Evolution of DevSecOps__
  - Traditional way: Security as an afterthought.
    - Security was not considered until after the release of an application where the patching was done afterwards
    - This is problematic as security fixes get more expensive the later the security issues are discovered
  - New DevSecOps: "Shifting Security left"
    - Security is considered all along the way from development, to deploying and after the app has already been released. 
  - How DevSecOps looks in practice:
    - Security professionals:
      - Create security policies
      - Select automation tools for detecting security issues
      - Train Developers and Operations teams
- __Types of Security Tests:__
  - _Static Application Security Testing (SAST)_
    - It does static analysis of the code (app is not running)
    - Identifies Security vulnerabilities in app's source code, configuration files, etc.
    - Looks for common coding errors, deviations from secure coding practices, etc.
    - Easiest form of security tests
  - _Software Composition Analysis (SCA)_
    - Check third-party and open source libraries and frameworks (dependencies of your application)
    - SCA tool goes through our dependencies and checks if any known vulnerabilities for that dependency and specific version and lists the vulnerable dependencies
    - It analyzes and tracks third-party components used in the app
  - Both SAST and SCA are static analysis because your app does not need to be running before you make these checks
    - Only requires access to the code and dependencies
  - Importance of private repo: if an attacker gets access to your code, they can do the static codes check just like you can, and if they discover the issues before you do, they can take advantage of the found vulnerabilities
  - _Dynamic Application Security Testing (DAST)_
    - Testing the app's running instance or deployed version
    - Checks for the application's vulnerability while it is running
    - Analyzing behavior and responses in real time
    - DAST tool simulates attacks; replicating how it would be interacted with by users and potential attackers
    - Basically, we are trying to emulate the hacker and trying to hack into or own application and systems
    - It does not require access to the code. Also called _Black Box Security Testing_
- Scanning code once is not enough; applications are developed continuously and therefore need continuous testing and fixing.
- Security scans and tests can slow down the CI/CD pipeline
  - Do only basic needed checks on every commit
    - Security checks only for affected code parts
    - Run 3rd-party library checks only when dependencies are changed
  - Comprehensive, complete security checks can be scheduled once per night as nightly build when no one's work is interrupted
- Manual functional and security tests
  - Some functionality and security tests cannot be automated or they are expensive and time consuming
  - Penetration testing
    - Often companies hire external experts for that
    - Important for highly sensitive systems like banking ...
- Logging and Monitoring
  - We might still miss something during the automated and manual testing or it might be that the issue appears later after the application was deployed
  - Logging and monitoring helps to alert the team if a security threat is detected
- Roles and Responsibilities:
  - Share responsibilities: 
    - Distribute responsibility for security across teams
      - Work with developers:
      - Makes security posture visible to the teams
      - Help the teams understand and how to fix the issues
      - Educate and raise awareness among teams about security best practices
      - This promotes a security-first mindset within the teams
    - DevSecOps works closely with security engineers who are more specialized in cybersecurity and are well versed in regulatory requirements and compliance frameworks
      - DevSecOps engineers can tap into their deep understanding of security principles to implement effective security measures
      - DevSecOps acts an intermediary between different teams
  - They architect DevSecops processes
  - Facilitates the integration of security testing into the development and deployment process
  - Provide guidance on secure coding standards, perform code reviews, etc
  - Establish mechanisms for continuous security monitoring, threat detection and vulnerability scanning

## Application Vulnerability Scanning

  - yarn: alternative for npm
  - `node_modules`: folder where yarn saves the downloaded modules from the web
  - `yarn.lock`: auto-generated file by yarn containing information of which versions of each dependencies were installed
  - Security is not centralized; rather it is an ongoing and integral part of the entire SDLC
  - __Secret Scanning with GitLeaks- Local Environment__
    - Prevent secrets in git repositories
    - Secrets: Anything that can be used to access a valuable asset
      - e.g. API Keys, passwords, tokens, private keys, authentication files
    - Secret scanning tool: tools that can scan source code and detect hard-coded secrets
      - e.g. GitLeaks
      - Fast light-weight and open-source secret scanner for git repos
      - Detects over 160 secret types, new types added all the time
    - Install GitLeaks: <https://akashchandwani.medium.com/what-is-gitleaks-and-how-to-use-it-a05f2fb5b034>
      - `brew install gitleaks` or 
      - install it via a docker image: <https://hub.docker.com/r/zricethezav/gitleaks>
        - `docker pull zricethezav/gitleaks:latest`
        - `export path_to_host_folder_to_scan=/Users/likimanip/code/devops/devsecops-nana/juice-shop`
        - `docker run -v ${path_to_host_folder_to_scan}:/path zricethezav/gitleaks:latest detect --source="/path" -v` # or `--verbose`
        - `gitleaks detect --source="./juice-shop" -v` or `gitleaks detect --verbose --source .`: Will scan repos, directories and files
      - <https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml>
      - With gitleaks.toml you can customize rules and write your own secret detection rules.
  - __Pre-commit Hook for Secret Scanning & Integrating GitLeaks in CI Pipeline__
    - Gitleaks scans through commits.
      - Parses the output of a `git log -p` command
      - Even though the sensitive data has been removed, the history of the repo remain intact
      - So this can still be a security concern, if unauthorized access or data mining of the repo's history occurs. While gitleaks check the code for leaked secrets, oncea commit is pushed, it's actually too late
      - We could change the password or revert git history but that is not an ideal situation. We can prevent this by scanning before the dev pushes to the repo.
      - Since we cannot reply on devs to run the scan, we can create a pre-commit hook
      - _Git Hooks_:
        - Git hooks is a Git functionality
        - It is a way to fire off custom scripts when certain important actions occur
        - There are different types of hooks:
          - precommit, pre-push, pre-rebase, ... etc.
          - "pre-commit" hook is fired when you are about to commit your changes
        - The hooks are all stored in the hooks subdirectory of the git golder: `.git/hooks`. You can view this by: `ls .git`
        - `vi .git/hooks/pre-commit`

        ```#!/bin/bash
        docker pull zricethezav/gitleaks:latest
        export path_to_host_folder_to_scan=/Users/likimanip/code/devops/devsecops-juice-shop
        docker run -v ${path_to_host_folder_to_scan}:/path zricethezav/gitleaks:latest detect --source="/path" --verbose
        ```
        - Make the file executable: `chmod +x .git/hooks/pre-commit` (The pre-commit will be ignored if the file doesn't have executable permissions)
        - The code will also not commit to the repo as long as the exposed secrets persist. This issue has to be fixed first, hence already boosting the security.
    - Client-side vs. Server-side hooks:
      - Server-side hooks: These scripts run before and after pushes to the server, so you can enforce this on the server-side
        - Different server-side hooks: pre-receive, upate, post-receive
  - __False Positives & Fixing Security Vulnerabilities__
    - We need to tweak our security tools to mitigate false positives:
      - Configure the tools properly
      - Keep them updated with the latest rules
      - Regularly review and refine results based on real-world context
    - Handling False positives:
      - We don't fail the build
        - You'll almost always face some amount of false positives
        - But if there are so many that it distracts the team, you need to take steps to reduce them
        - We will integrate it into the pipeline to optimize it step by step, so you don't interrupt the developer workflow until you mature the tool

        ```.gitlab-ci.yml
          gitleaks:
          stage: test
          image:
              name: zricethezav/gitleaks
              entrypoint: [""] # will not execute gitleaks immediately, waits until script is called
          script:
              - gitleaks detect --verbose --source .
          allow_failure: true
        ``` 

      - Adjust the tool configuration
        - e.g Custom configuration that is appllication specific

      ```gitleaks.toml
        [extend]
        useDefault = true

        [allowlist]
        paths = ['test', '.*\/test\/.*']
      ```
    - This will ignore the files names above to avoid false positives
    
    - Ps. gitleaks failed to detect the false negatives with the hardcoded docker password. That needs to be communicated to developers because sometimes the scanning tools do not capture all secrets
    - Record this as variables in gitlab and change the gitlab-ci.yml to reflect the change:

      ```.gitlab-ci.yml
      variables:
        DOCKER_PASS: $DOCKER_PASS
        DOCKER_USER: $DOCKER_USER
      ```

    - Set strict permissions on git repos
      - Granular permission system
      - Restrict access to project settings
  
  - __Integrate SAST Scans in Release Pipeline__
    - SAST(Static Application Security Testing) is code analysis that is performed before the app is executed
    - It identifies the security vulnerabilities in the app's source code, config files, etc.
    - There are different SAST tools based on programming languages
      - Each language has its own syntax, semantics and potential security pitfalls, which is why specialized SAST tools are created
      - Language-specific vulnerabilities
      - eg. njsscan, deepScan, Flow: static security code scanner for Js apps,
        - SpotBugs, CheckStyle, Error-Prone for Java apps,
        - Bandit, Pysa for Python apps
    - There are SAST tools that can scan multiple languages eg. Semgrep, Snyk Code, SonarQube, CHeckmarx, ... etc
    - <https://hub.docker.com/r/opensecurity/njsscan>
  - It is important to use different tools because they will catch different vulnerabilites, based on the organization's needs, available resources, ... etc.
  - There are different levels of severity
    - Refers to the degree of imapct or potential harm that a security vulnerability could have on a system, app or data
    - Often categorized into:
      - Critical or High Severity
      - Medium Severity
      - Low or Warning
      - Informational
    - This helps us understand the level of risk posed by particular vulnerability and determine how urgently it needs to be addressed, and what can be ignored or marked as optional
    - So the configuration to fail the build can be configured based on the severity level
  - Semgrep:
    - Ref:
      - <https://hub.docker.com/search?q=semgrep>
      - <https://semgrep.dev/docs/semgrep-ci/sample-ci-configs>
      - <https://semgrep.dev/docs/ignoring-files-folders-code#understand-semgrep-defaults>
    - Free open-source SAST tool
    - Supports multiple langiages like C#, Go, Java, JS, Ruby, Python, PHP, Scala
    - You can specify the language it will be scanning

## Vulnerability Management and Remediation

- __Generate Security Scanning Reports__
  - Vulnerability management tools centrally manage vulnerability findings across different tools
    - Enriches and refines vulnerability data
    - Triage vulnerabilities and push findings to other systems
  - e.g. DefectDojo: OpenSource vulnerability management tool
    - How it Works:
      - Findings in files from the logs
      - Run DefetDojo
      - Feed report files to DefectDojo
    - Tools produce report files in a format that the visualization tool can consume
    - Each tool produces its wn type of security report so DefectDojo is able to interpret these different report files, we need to specify the tool the report is coming from.
    - Generate scan report files:
      - Produce file reports for each scan tool
      - Import to DefectDojo
      
      ```.gitlab-ci.yml
      ...
      script:
        - gitleaks detect --verbose --source . -f json -r gitleaks.json
      allow_failure: true
      ...

      script:
        - njsscan --exit-warning . --sarif -o njsscan.sarif
      ...


      ```
      - This will generate a json file called gitleaks.json
      - Then configure the artifacts attribute to save that file outside of the pipeline for use by DefectDojo:

      ```.gitlab-ci.yml
      ...
      script:
        - gitleaks detect --verbose --source . -f json -r gitleaks.json
      allow_failure: true
      artifacts:
        when: always  # Configure when it should be saved, if always..regardless of failure
        paths:
          - gitleaks.json
      ...
      ```
      - The pipeline will then create artifacts that can be dowloaded and imported to DefectDojo
- __Introduction to Defectdojo, Managing Security Findings, CWEs__
  - Ref:
    - DefectDojo
      - Installation: <https://documentation.defectdojo.com/getting_started/installation/>
      - Image: <https://hub.docker.com/r/defectdojo/defectdojo-django>
      - Demo: <https://demo.defectdojo.org/>
    - CWE
      - CWE List: <https://cwe.mitre.org/data/definitions/699.html>
      - OWASP Top 10 Mapping: <https://cwe.mitre.org/data/definitions/1344.html>
  - DefectDojo serves as an aggregator and provides a unified and streamlined view for security tools
  - Smart features to enhance and tune the results from your security tools (Merge findings, remember false positives, distill duplicates ...)
  - You can also push the findings to other tools. Bi-directional integration with Jira, Notifications, Google Sheets synchronization, etc.
  - Enables traceability among multiple projects/ test cycles and allows for fine-grained reporting
  - Create product type > add product > findings/import scan results.
    - Scan types: semgrep.json, SARIF, gitleaks.json ...
  - Note on the demo UI app: any data will be public and data is reset ever hour, it does not persist data
  - There are 2 types of engagment:
    - Interactive Engagement: Findings are uploaded by the engineer
    - CI/CD Engagement: For automated intergration with a CI/CD pipeline
  - Analyze Findings
    - Findings > view active findings
  - CWE: Common Weakness Enumeration: More detailed list of security threats
    - Description of the issue, what causes it and how it can be fixed
    - Maps to OWASP 10 categories
    - It is a comnnunity developed list of common software and hardness weakness types. Separate from OWASP
    - Main idea: Stop vulnerabilities at the source by educating engineers on how to eliminate the most commin mistakes before products are delivered
    - Discuss weaknesses in a common language
    - Leverage a common baseline standard for weakness identification and mitigation
    - Express vulnerability in numeric information
  - Use scan results to educate
    - Main purpose of security scans in the development process is to train developers continuously in various security topics because everyone is responsible for the security of the applications
- __Automate Uploading Security Scan Results to DefectDojo__
    - 