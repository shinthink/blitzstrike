- id: py-xss-escape
- language: python
- vulnerable: false
- sink_type: html_render
```python
name = request.args.get("name")
return "<div>" + escape(name) + "</div>"
```
