# Javascript/Dependencies

## Purpose

To test that package audits pick up a vulnerable package version.

## Test

Run either `npm audit` or `yarn audit`.

## Expected Results

```markdown
squirrelly  <=8.0.8
Severity: high
Insecure template handling in Squirrelly - https://github.com/advisories/GHSA-q8j6-pwqx-pm96
fix available via `npm audit fix --force`
Will install squirrelly@9.0.0, which is a breaking change
node_modules/squirrelly

1 high severity vulnerability
```
