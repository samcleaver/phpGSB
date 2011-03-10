<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Version 0.2.1 (ALPHA) - Not recommended for production use
Released under New BSD License (see LICENSE)
Copyright (c) 2010-2011, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.

UPGRADER FROM 0.2 to 0.2.1 - RUN ONCE
*/
require("phpgsb.class.php");
$phpgsb = new phpGSB("DATABASE_NAME","DATABASE_USERNAME","DATABASE_PASSWORD");
$phpgsb->usinglists = array('googpub-phish-shavar','goog-malware-shavar');
//Add Some More Indexes
foreach($phpgsb->usinglists as $value)
	{
	mysql_query("ALTER TABLE `$value-a-hosts` ADD INDEX ( `Hostkey` );");
	mysql_query("ALTER TABLE `$value-a-prefixes` ADD INDEX ( `Hostkey` );");
	mysql_query("ALTER TABLE `$value-s-prefixes` ADD INDEX ( `Hostkey` );");
	}
echo "Congratulations! PHPGSB Table Layout Updated!";
?>