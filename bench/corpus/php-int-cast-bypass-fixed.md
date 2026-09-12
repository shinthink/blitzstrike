- id: php-int-cast-bypass-fixed
- language: php
- vulnerable: false
- sink_type: sql_execution
```php
<?php
class Query {
  public function run($params) {
    $where = "";
    if ( ! empty( $params["ids"] ) ) {
      $ids = implode( ",", array_map( "intval", (array) $params["ids"] ) );
      $where .= " AND id NOT IN ($ids) ";
    }
    return $db->query("SELECT * FROM t WHERE 1=1 $where");
  }
}
$q = $_GET;
$w = new Query();
$w->run($q);
```
