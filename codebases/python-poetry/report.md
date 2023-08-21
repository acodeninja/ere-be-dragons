# Security Report for python

## Summary

This security report was conducted on 18/07/2023 at 12:01:28 (UTC+1).
A total of 3 issue(s) were found, 1 of which may require immediate attention.

The following technical impacts may arise if an adversary successfully exploits one of the issues found by this scan.

* **Confidentiality**: Read Application Data, Read Memory, Execute Unauthorized Code or Commands
* **Availability**: DoS: Crash, Exit, or Restart
* **Integrity**: Unexpected State, Modify Memory, Execute Unauthorized Code or Commands
* **Access Control**: Gain Privileges or Assume Identity

### Contents

* [Issue Statistics](#statistics)
* [Overview of Issues](#overview-of-issues)
* [Vulnerabilities](#vulnerabilities)
* [Additional Information](#additional-information)
  * [What are severity levels?](#what-are-severity-levels)

## Statistics

This report found issues with the following severities.

**Critical**: 1 | **High** 0 | **Medium** 0 | **Low** 2 | **Informational** 0 | **Unknown** 0

To gain a better understanding of the severity levels please see [the appendix](#what-are-severity-levels).

## Overview of Issues

<a id="CWE-20"></a>
### Improper Input Validation

The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.


Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with other components. When software does not validate input properly, an attacker is able to craft the input in a form that is not expected by the rest of the application. This will lead to parts of the system receiving unintended input, which may result in altered control flow, arbitrary control of a resource, or arbitrary code execution.Input validation is not the only technique for processing input, however. Other techniques attempt to transform potentially-dangerous input into something safe, such as filtering ([CWE-790](https://cwe.mitre.org/data/definitions/790.html)) - which attempts to remove dangerous inputs - or encoding/escaping ([CWE-116](https://cwe.mitre.org/data/definitions/116.html)), which attempts to ensure that the input is not misinterpreted when it is included in output to another component. Other techniques exist as well (see [CWE-138](https://cwe.mitre.org/data/definitions/138.html) for more examples.)Input validation can be applied to:raw data - strings, numbers, parameters, file contents, etc.metadata - information about the raw data, such as headers or sizeData can be simple or structured. Structured data can be composed of many nested layers, composed of combinations of metadata and raw data, with other simple or structured data.Many properties of raw data or metadata may need to be validated upon entry into the code, such as:specified quantities such as size, length, frequency, price, rate, number of operations, time, etc.implied or derived quantities, such as the actual size of a file instead of a specified sizeindexes, offsets, or positions into more complex data structuressymbolic keys or other elements into hash tables, associative arrays, etc.well-formedness, i.e. syntactic correctness - compliance with expected syntax lexical token correctness - compliance with rules for what is treated as a tokenspecified or derived type - the actual type of the input (or what the input appears to be)consistency - between individual data elements, between raw data and metadata, between references, etc.conformance to domain-specific rules, e.g. business logic equivalence - ensuring that equivalent inputs are treated the sameauthenticity, ownership, or other attestations about the input, e.g. a cryptographic signature to prove the source of the dataImplied or derived properties of data must often be calculated or inferred by the code itself. Errors in deriving properties may be considered a contributing factor to improper input validation. Note that "input validation" has very different meanings to different people, or within different classification schemes. Caution must be used when referencing this CWE entry or mapping to it. For example, some weaknesses might involve inadvertently giving control to an attacker over an input when they should not be able to provide an input at all, but sometimes this is referred to as input validation.Finally, it is important to emphasize that the distinctions between input validation and output escaping are often blurred, and developers must be careful to understand the difference, including how input validation is not always sufficient to prevent vulnerabilities, especially when less stringent data types must be supported, such as free-form text. Consider a SQL injection scenario in which a person's last name is inserted into a query. The name "O'Reilly" would likely pass the validation step since it is a common last name in the English language. However, this valid name cannot be directly inserted into the database because it contains the "'" apostrophe character, which would need to be escaped or otherwise transformed. In this case, removing the apostrophe might reduce the risk of SQL injection, but it would produce incorrect behavior because the wrong name would be recorded.


#### Consequences

Using a vulnerability of this type an attacker may be able to affect the system in the following ways. 

* **Availability**: DoS: Crash, Exit, or Restart

> An attacker could provide unexpected values and cause a program crash or excessive consumption of resources, such as memory and CPU.

* **Confidentiality**: Read Memory

> An attacker could read confidential data if they are able to control resource references.

* **Integrity**: Modify Memory
* **Confidentiality**: Execute Unauthorized Code or Commands
* **Availability**

> An attacker could use malicious input to modify data or possibly alter control flow in unexpected ways, including arbitrary command execution.


For more information see [CWE-20](https://cwe.mitre.org/data/definitions/20.html).

<a id="CWE-259"></a>
### Use of Hard-coded Password

The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components.


A hard-coded password typically leads to a significant authentication failure that can be difficult for the system administrator to detect. Once detected, it can be difficult to fix, so the administrator may be forced into disabling the product entirely. There are two main variations:Inbound: the product contains an authentication mechanism that checks for a hard-coded password.Outbound: the product connects to another system or component, and it contains hard-coded password for connecting to that component.In the Inbound variant, a default administration account is created, and a simple password is hard-coded into the product and associated with that account. This hard-coded password is the same for each installation of the product, and it usually cannot be changed or disabled by system administrators without manually modifying the program, or otherwise patching the product. If the password is ever discovered or published (a common occurrence on the Internet), then anybody with knowledge of this password can access the product. Finally, since all installations of the product will have the same password, even across different organizations, this enables massive attacks such as worms to take place.The Outbound variant applies to front-end systems that authenticate with a back-end service. The back-end service may require a fixed password which can be easily discovered. The programmer may simply hard-code those back-end credentials into the front-end product. Any user of that program may be able to extract the password. Client-side systems with hard-coded passwords pose even more of a threat, since the extraction of a password from a binary is usually very simple.


#### Consequences

Using a vulnerability of this type an attacker may be able to affect the system in the following ways. 

* **Access Control**: Gain Privileges or Assume Identity

> If hard-coded passwords are used, it is almost certain that malicious users will gain access through the account in question.


For more information see [CWE-259](https://cwe.mitre.org/data/definitions/259.html).

<a id="CWE-703"></a>
### Improper Check or Handling of Exceptional Conditions

The product does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the product.




#### Consequences

Using a vulnerability of this type an attacker may be able to affect the system in the following ways. 

* **Confidentiality**: Read Application Data
* **Availability**: DoS: Crash, Exit, or Restart
* **Integrity**: Unexpected State



For more information see [CWE-703](https://cwe.mitre.org/data/definitions/703.html).

<a id="CWE-918"></a>
### Server-Side Request Forgery (SSRF)

The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.


By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers from accessing the URLs directly. The server can be used as a proxy to conduct port scanning of hosts in internal networks, use other URLs such as that can access documents on the system (using file://), or use other protocols such as gopher:// or tftp://, which may provide greater control over the contents of requests.


#### Consequences

Using a vulnerability of this type an attacker may be able to affect the system in the following ways. 

* **Confidentiality**: Read Application Data


* **Integrity**: Execute Unauthorized Code or Commands



For more information see [CWE-918](https://cwe.mitre.org/data/definitions/918.html).


## Vulnerabilities

### Critical Severity

#### Vulnerable Third-Party Library `cairosvg` (version 2.6.0)

**Severity**: [Critical](#Critical) | **Type**: dependency | **Fix**: unknown | **Found By**: [@continuous-security/scanner-python-pip-audit](https://www.npmjs.com/package/@continuous-security/scanner-python-pip-audit)

CairoSVG is an SVG converter based on Cairo, a 2D graphics library. Prior to version 2.7.0, Cairo can send requests to external hosts when processing SVG files. A malicious actor could send a specially crafted SVG file that allows them to perform a server-side request forgery or denial of service. Version 2.7.0 disables CairoSVG's ability to access other files online by default.


##### References

[CVE-2023-27586](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27586) | [CWE-20](#CWE-20) | [CWE-918](#CWE-918) | [GHSA-rwmf-w63j-p7gv](https://osv.dev/vulnerability/GHSA-rwmf-w63j-p7gv) | [PYSEC-2023-9](https://osv.dev/vulnerability/PYSEC-2023-9)


### Low Severity

#### Try, Except, Pass detected. 

**Severity**: [Low](#Low) | **Type**: code smell | **Fix**: unknown | **Found By**: [@continuous-security/scanner-python-bandit](https://www.npmjs.com/package/@continuous-security/scanner-python-bandit)

The product does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the product.

##### Instances

The following examples were found in the application.

`main.py` (starting on line: 4)
```python
2|   try:
3|     print('thing')
4|   except:
5|     pass
6| 
```

##### References

[CWE-703](#CWE-703)


#### Possible hardcoded password: 'password' 

**Severity**: [Low](#Low) | **Type**: code smell | **Fix**: unknown | **Found By**: [@continuous-security/scanner-python-bandit](https://www.npmjs.com/package/@continuous-security/scanner-python-bandit)

The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components.

##### Instances

The following examples were found in the application.

`main.py` (starting on line: 8)
```python
 6| 
 7| def login(username, password):
 8|   if password == 'password':
 9|     return True
10|   return False
```

##### References

[CWE-259](#CWE-259)




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
