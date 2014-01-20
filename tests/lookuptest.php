<?php
$options = array("database" => "gsb",
                 "username" => "root",
                 "password" => "",
                 "host" => "localhost",
                 "port" => false);

require("../lib/phpgsb.lookup.php");
echo "<pre>";
$phpgsb = new phpGSB_Lookup(3, true);
$phpgsb->setAPIKey("ABQIAAAAxYUTHSyYcCo4eElEhFN-vxSP9Emz4isnJG6OrHGeg3i34CLIIA");
$phpgsb->setAdapter('mysql', $options);
$phpgsb->doLookup("http://google.com/");

echo "</pre>";
?>
