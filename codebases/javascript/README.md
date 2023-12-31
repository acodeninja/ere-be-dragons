# Javascript

## Vulnerabilities

* Remote code execution
* XSS (Cross-site Scripting)
* CSRF (Cross-site Request Forgery)

## Test

### [continuous-security](https://github.com/acodeninja/continuous-security)

[Report](./report.md)

### Audit

Run either `npm audit` or `yarn audit`.

#### Expected Results

```markdown
squirrelly  <=8.0.8
Severity: high
Insecure template handling in Squirrelly - https://github.com/advisories/GHSA-q8j6-pwqx-pm96
fix available via `npm audit fix --force`
Will install squirrelly@9.0.0, which is a breaking change
node_modules/squirrelly

1 high severity vulnerability
```

### Dynamic

1. Install dependencies `npm install`.
2. Run the application `npm start`.
3. Run a [ZAP](https://www.zaproxy.org/) automated scan against `http://localhost:3000`.

#### Expected Results (truncated)

```markdown
# ZAP Scanning Report

## Summary of Alerts

| Risk Level    | Number of Alerts |
|---------------|------------------|
| High          | 3                |
| Medium        | 4                |
| Low           | 3                |
| Informational | 2                |

## Alerts

| Name                                                                      | Risk Level    | Number of Instances |
|---------------------------------------------------------------------------|---------------|---------------------|
| Cross Site Scripting (DOM Based)                                          | High          | 7                   |
| Cross Site Scripting (Persistent)                                         | High          | 1                   |
| Cross Site Scripting (Reflected)                                          | High          | 2                   |
| Absence of Anti-CSRF Tokens                                               | Medium        | 5                   |
| CSP: Wildcard Directive                                                   | Medium        | 10                  |
| Content Security Policy (CSP) Header Not Set                              | Medium        | 5                   |
| Missing Anti-clickjacking Header                                          | Medium        | 5                   |
| Private IP Disclosure                                                     | Low           | 3                   |
| Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | Low           | 15                  |
| X-Content-Type-Options Header Missing                                     | Low           | 5                   |
| Information Disclosure - Suspicious Comments                              | Informational | 3                   |
| User Agent Fuzzer                                                         | Informational | 36                  |
```
