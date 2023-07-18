# Security Report for ruby

## Summary

This security report was conducted on 18/07/2023 at 12:08:30 (UTC+1).
A total of 4 issue(s) were found, 1 of which may require immediate attention.

The following technical impacts may arise if an adversary successfully exploits one of the issues found by this scan.

* **Integrity**: Execute Unauthorized Code or Commands, Read Application Data
* **Confidentiality**: Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity
* **Availability**: Modify Application Data, Execute Unauthorized Code or Commands
* **Access Control**

### Contents

* [Issue Statistics](#statistics)
* [Overview of Issues](#overview-of-issues)
* [Vulnerabilities](#vulnerabilities)
* [Additional Information](#additional-information)
  * [What are severity levels?](#what-are-severity-levels)

## Statistics

This report found issues with the following severities.

**Critical**: 1 | **High** 2 | **Medium** 0 | **Low** 0 | **Informational** 0 | **Unknown** 1

To gain a better understanding of the severity levels please see [the appendix](#what-are-severity-levels).

## Overview of Issues

<a id="CWE-77"></a>
### Improper Neutralization of Special Elements used in a Command ('Command Injection')

The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.


Command injection vulnerabilities typically occur when:1. Data enters the application from an untrusted source.2. The data is part of a string that is executed as a command by the application.3. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have.Many protocols and products have their own custom command language. While OS or shell command strings are frequently discovered and targeted, developers may not realize that these other command languages might also be vulnerable to attacks.Command injection is a common problem with wrapper programs.


#### Consequences

Using a vulnerability of this type an attacker may be able to affect the system in the following ways. 

* **Integrity**: Execute Unauthorized Code or Commands
* **Confidentiality**
* **Availability**

> If a malicious user injects a character (such as a semi-colon) that delimits the end of one command and the beginning of another, it may be possible to then insert an entirely new and unrelated command that was not intended to be executed.


For more information see [CWE-77](https://cwe.mitre.org/data/definitions/77.html).

<a id="CWE-91"></a>
### XML Injection (aka Blind XPath Injection)

The product does not properly neutralize special elements that are used in XML, allowing attackers to modify the syntax, content, or commands of the XML before it is processed by an end system.


Within XML, special elements could include reserved words or characters such as "&lt;", "&gt;", """, and "&amp;", which could then be used to add new data or modify XML syntax.


#### Consequences

Using a vulnerability of this type an attacker may be able to affect the system in the following ways. 

* **Confidentiality**: Execute Unauthorized Code or Commands
* **Integrity**: Read Application Data
* **Availability**: Modify Application Data



For more information see [CWE-91](https://cwe.mitre.org/data/definitions/91.html).

<a id="CWE-287"></a>
### Improper Authentication

When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.




#### Consequences

Using a vulnerability of this type an attacker may be able to affect the system in the following ways. 

* **Integrity**: Read Application Data
* **Confidentiality**: Gain Privileges or Assume Identity
* **Availability**: Execute Unauthorized Code or Commands
* **Access Control**

> This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code.


For more information see [CWE-287](https://cwe.mitre.org/data/definitions/287.html).


## Vulnerabilities

### Critical Severity

#### Vulnerable Third-Party Library `ruby-saml` (version 0.9.2)

**Severity**: [Critical](#Critical) | **Type**: dependency | **Fix**: upgrade to '>= 1.0.0' | **Found By**: [@continuous-security/scanner-ruby-bundle-audit](https://www.npmjs.com/package/@continuous-security/scanner-ruby-bundle-audit)

ruby-saml gem is vulnerable to XPath injection


##### References

[CVE-2015-20108](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-20108) | [CWE-77](#CWE-77) | [GHSA-r364-2pj4-pf7f](https://osv.dev/vulnerability/GHSA-r364-2pj4-pf7f)


### High Severity

#### Vulnerable Third-Party Library `ruby-saml` (version 0.9.2)

**Severity**: [High](#High) | **Type**: dependency | **Fix**: upgrade to '>= 1.3.0' | **Found By**: [@continuous-security/scanner-ruby-bundle-audit](https://www.npmjs.com/package/@continuous-security/scanner-ruby-bundle-audit)

XML signature wrapping attack


##### References

[CVE-2016-5697](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5697) | [CWE-91](#CWE-91) | [GHSA-36p7-xjw8-h6f2](https://osv.dev/vulnerability/GHSA-36p7-xjw8-h6f2)


#### Vulnerable Third-Party Library `ruby-saml` (version 0.9.2)

**Severity**: [High](#High) | **Type**: dependency | **Fix**: upgrade to '>= 1.7.0' | **Found By**: [@continuous-security/scanner-ruby-bundle-audit](https://www.npmjs.com/package/@continuous-security/scanner-ruby-bundle-audit)

Authentication bypass via incorrect XML canonicalization and DOM traversal


##### References

[CVE-2017-11428](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11428) | [CWE-287](#CWE-287) | [GHSA-x2fr-v8wf-8wwv](https://osv.dev/vulnerability/GHSA-x2fr-v8wf-8wwv)


### Unknown Severity

#### Vulnerable Third-Party Library `ruby-saml` (version 0.9.2)

**Severity**: [Unknown](#Unknown) | **Type**: dependency | **Fix**: upgrade to '>= 1.0.0' | **Found By**: [@continuous-security/scanner-ruby-bundle-audit](https://www.npmjs.com/package/@continuous-security/scanner-ruby-bundle-audit)

Ruby-Saml Gem is vulnerable to entity expansion attacks





## Additional Information

### What are severity levels?

Issue severity is scored using the [Common Vulnerability Scoring System](https://www.first.org/cvss/) (CVSS) where
such data is available. Severity levels do not represent the risk associated with an issue as risk depends on your
specific context. Severity scoring does however give an indication of the ease of exploitation and potential scope of an
attacks effect on an application.

#### Critical

Exploitation will likely lead to an attacker gaining administrative access to the application and infrastructure that
supports it. Exploiting critical vulnerabilities is usually trivial and will generally not require prior access to the
application. **A development team should aim to resolve these issues immediately by mitigating or directly resolving the
issue**.

#### High

Exploitation could lead to an attacker gaining elevated access to the application and the infrastructure that supports
it. It is likely that an attacker will not find exploitation trivial. Such exploitation could lead to significant data
loss or downtime.

#### Medium

Exploitation could lead to an attacker gaining limited access to the application. Exploiting vulnerabilities may require
an attacker to manipulate users to gain access to their credentials. Such exploitation could lead to limited data loss
or downtime.

#### Low

Exploitation will likely have very little impact on the application, and it is unlikely that an attacker will gain any
meaningful access to the application. Exploiting an issue of this severity will potentially require physical access to
the infrastructure that supports the application.

#### Informational

While not part of the CVSS scoring specification, several security analysis tools use this severity level to indicate
that an issue is a matter of best practice. It is extremely unlikely that issues with this severity will lead to an
attacker gaining access to any application components.

#### Unknown

This severity level is used when the analysis tool used to perform a scan of the application does not associate any kind
of severity level with the issues or vulnerabilities it finds. Issues with an unknown severity should be investigated by
application developers and project stakeholders to establish the ease of exploitation, scope of any potential impact and
the specific risks associated.
