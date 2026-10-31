# Detection prompt template

```
You are reviewing the following source snippet for security vulnerabilities.

<source>
{source}
</source>

Report each finding as JSON:
{
  "rule_id": "sqli|xss|cmdi|secrets|pathtraversal|weakcrypto|ssrf|deserialization|openredirect",
  "line": <1-based line number>,
  "snippet": "<the offending line>",
  "reason": "<why this is exploitable>"
}

Only report unambiguous anti-patterns. If the code is safe, return an empty list.
```

## Reuse notes

- The `<source>` block is the only variable; the rest is static.
- Keep the instruction narrow ("unambiguous anti-patterns") to maximize
  precision at the cost of recall -- you can always run a second, looser pass.
