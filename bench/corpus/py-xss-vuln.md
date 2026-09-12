- id: py-xss-vuln
- language: python
- vulnerable: true
- sink_type: html_render
```python
name = request.args.get("name")
return render_template_string("<p>" + name + "</p>")
```
