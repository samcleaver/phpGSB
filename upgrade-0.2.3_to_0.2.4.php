<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Released under New BSD License (see LICENSE)
Copyright (c) 2010-2012, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.

UPGRADER FROM 0.2.3 to 0.2.4 - RUN ONCE
*/
require("phpgsb.class.php");
$phpgsb = new phpGSB("DATABASE_NAME","DATABASE_USERNAME","DATABASE_PASSWORD");
$phpgsb->usinglists = array('googpub-phish-shavar','goog-malware-shavar');
//Reset database
$phpgsb->resetDatabase();
echo "Congratulations! PHPGSB Database Reset, Please Wait 24 Hours For It To Fully Sync!";
?>