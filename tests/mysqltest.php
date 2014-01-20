<?php
$options = array("database" => "gsb",
                 "username" => "root",
                 "password" => "",
                 "host" => "localhost",
                 "port" => false);

require("../lib/phpgsb.updater.php");
echo "<pre>";
$phpgsb = new phpGSB_Updater(3, true);
$phpgsb->setAPIKey("ABQIAAAAxYUTHSyYcCo4eElEhFN-vxSP9Emz4isnJG6OrHGeg3i34CLIIA");
$phpgsb->setAdapter('mysql', $options);
$phpgsb->runUpdate();

echo "</pre>";
?>
