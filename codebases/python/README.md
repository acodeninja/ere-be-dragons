# Python

## Test

### Audit

Run `pip-audit`.

#### Expected Results

```markdown
Found 1 known vulnerability in 1 package
Name     Version ID           Fix Versions
-------- ------- ------------ ------------
cairosvg 2.6.0   PYSEC-2023-9 2.7.0
```

### Static Analysis

Run `bandit -r ./main.py`.

#### Expected Results

```markdown
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
Severity: Low   Confidence: High
CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b110_try_except_pass.html
Location: ./main.py:4:2
3           print('thing')
4         except:
5           pass
6

--------------------------------------------------
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'password'
Severity: Low   Confidence: Medium
CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b105_hardcoded_password_string.html
Location: ./main.py:8:17
7       def login(username, password):
8         if password == 'password':
9           return True

--------------------------------------------------
```
