<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Version 0.2 (ALPHA) - Not recommended for production use
Released under New BSD License (see LICENSE)
Copyright (c) 2010-2011, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.

UPGRADER FROM 0.1.3 to 0.2 - RUN ONCE
*/
require("phpgsb.class.php");
$phpgsb = new phpGSB("DATABASE_NAME","DATABASE_USERNAME","DATABASE_PASSWORD");
$phpgsb->usinglists = array('googpub-phish-shavar','goog-malware-shavar');
//Install MySQL tables
foreach($phpgsb->usinglists as $value)
	{
	mysql_query("ALTER TABLE `goog-malware-shavar-a-hosts` ADD INDEX ( `Hostkey` ), ENGINE = InnoDB;");
	mysql_query("ALTER TABLE `$value-a-index` ENGINE = InnoDB;");
	mysql_query("ALTER TABLE `$value-a-prefixes` ENGINE = InnoDB;");
	mysql_query("ALTER TABLE `$value-s-hosts` ADD INDEX ( `Hostkey` ), ENGINE = InnoDB;");
	mysql_query("ALTER TABLE `$value-s-index` ENGINE = InnoDB;");
	mysql_query("ALTER TABLE `$value-s-prefixes` ENGINE = InnoDB;");
	}
echo "Congratulations! PHPGSB Table Layout Updated!";
?>