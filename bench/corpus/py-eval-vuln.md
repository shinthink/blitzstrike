- id: py-eval-vuln
- language: python
- vulnerable: true
- sink_type: code_execution
```python
code = request.args.get("code")
eval(code)
```
