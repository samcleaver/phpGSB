<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Version 0.1 (ALPHA) - Not recommended for production use
Released under New BSD License (see LICENSE)
Copyright (c) 2010, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.

UPDATER EXAMPLE
*/
require("phpgsb.class.php");
$phpgsb = new phpGSB("DATABASE_NAME","DATABASE_USERNAME","DATABASE_PASSWORD");
//Obtain an API key from: http://code.google.com/apis/safebrowsing/key_signup.html
$phpgsb->apikey = "API_KEY_HERE";
$phpgsb->usinglists = array('googpub-phish-shavar','goog-malware-shavar');
$phpgsb->runUpdate();
$phpgsb->close();
?>