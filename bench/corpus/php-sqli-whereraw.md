- id: php-sqli-whereraw
- language: php
- vulnerable: true
- sink_type: sql_execution
```php
<?php
$id = $_GET["id"];
DB::table("t")->whereRaw("id = $id")->get();
```
