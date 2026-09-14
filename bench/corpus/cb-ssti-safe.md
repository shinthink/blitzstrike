- id: cb-ssti-safe
- language: javascript
- vulnerable: false
- detector: complex_bugs

```js
const html = _.template("<h1>static</h1>");
```
