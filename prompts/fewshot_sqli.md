# Few-shot: SQL injection

## Example 1 (vulnerable)

Input:
```
query = "SELECT * FROM users WHERE name = '" + username + "'"
```

Output:
```
{"rule_id": "sqli", "line": 1, "reason": "string concatenation into SQL"}
```

## Example 2 (safe)

Input:
```
cur.execute("SELECT * FROM users WHERE name = ?", (username,))
```

Output:
```
[]
```

## Rule

Parameterized queries are the fix. String concatenation / f-string / `.format`
into a SQL string is the bug.
