- id: php-int-cast-bypass-vuln
- language: php
- vulnerable: true
- sink_type: sql_execution
```php
<?php
class Query {
  public function run($params) {
    $where = "";
    if ( ! empty( $params["ids"] ) ) {
      if ( is_array( $params["ids"] ) ) {
        $params["ids"] = array_map( "intval", $params["ids"] );
      }
      $ids = implode( ",", (array) $params["ids"] );
      $where .= " AND id NOT IN ($ids) ";
    }
    return $db->query("SELECT * FROM t WHERE 1=1 $where");
  }
}
$q = $_GET;
$w = new Query();
$w->run($q);
```
