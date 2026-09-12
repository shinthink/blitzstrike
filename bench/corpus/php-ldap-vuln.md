- id: php-ldap-vuln
- language: php
- vulnerable: true
- sink_type: ldap_injection
```php
<?php
$filter = $_GET["filter"];
$res = ldap_search($conn, "dc=example,dc=com", $filter);
```
