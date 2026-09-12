- id: py-ssti-vuln
- language: python
- vulnerable: true
- sink_type: template_injection
```python
tpl = request.args.get("tpl")
return render_template_string(tpl)
```
