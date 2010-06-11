<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Version 0.1 (ALPHA) - Not recommended for production use
Released under New BSD License (see LICENSE)
Copyright (c) 2010, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.

LOOKUP EXAMPLE
*/
require("phpgsb.class.php");
$phpgsb = new phpGSB("beaverco_gsb","beaverco_gsb","HH!GXJ7k_u9_");
//Obtain an API key from: http://code.google.com/apis/safebrowsing/key_signup.html
$phpgsb->apikey = "ABQIAAAAROhEx3lHT1tGSVwkVTOR4hSngZquPU5ScO4TcEoShNPaIfb44A";
$phpgsb->usinglists = array('googpub-phish-shavar','goog-malware-shavar');
//Should return false (not phishing or malware)
var_dump($phpgsb->doLookup('http://www.google.com'));
//Should return true, malicious URL
var_dump($phpgsb->doLookup('http://www.gumblar.cn'));
$phpgsb->close();
?>