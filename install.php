<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Version 0.1 (ALPHA) - Not recommended for production use
Released under New BSD License (see LICENSE)
Copyright (c) 2010, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.

INITIAL INSTALLER - RUN ONCE (or more than once if you're adding a new list!)
*/
require("phpgsb.class.php");
$phpgsb = new phpGSB("DATABASE_NAME","DATABASE_USERNAME","DATABASE_PASSWORD");
$phpgsb->usinglists = array('googpub-phish-shavar','goog-malware-shavar');
//Install MySQL tables
foreach($phpgsb->usinglists as $value)
	{
	//Create ADD tables
	mysql_query("CREATE TABLE IF NOT EXISTS `$value-a-hosts` (
  `ID` int(255) NOT NULL auto_increment,
  `Hostkey` varchar(8) NOT NULL,
  `Chunknum` int(255) NOT NULL,
  `Count` varchar(2) NOT NULL default '0',
  `FullHash` varchar(70) NOT NULL,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 ;");
	mysql_query("CREATE TABLE IF NOT EXISTS `$value-a-index` (
  `ChunkNum` int(255) NOT NULL auto_increment,
  `Chunklen` int(255) NOT NULL default '0',
  PRIMARY KEY  (`ChunkNum`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 ;");	
	mysql_query("CREATE TABLE IF NOT EXISTS `$value-a-prefixes` (
  `ID` int(255) NOT NULL auto_increment,
  `Hostkey` varchar(8) NOT NULL,
  `Prefix` varchar(255) NOT NULL,
  `FullHash` varchar(70) NOT NULL,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 ;");	
	//Create SUB tables
	mysql_query("CREATE TABLE IF NOT EXISTS `$value-s-hosts` (
  `ID` int(255) NOT NULL auto_increment,
  `Hostkey` varchar(8) NOT NULL,
  `Chunknum` int(255) NOT NULL,
  `Count` varchar(2) NOT NULL default '0',
  `FullHash` varchar(70) NOT NULL,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 ;");
	mysql_query("CREATE TABLE IF NOT EXISTS `$value-s-index` (
  `ChunkNum` int(255) NOT NULL auto_increment,
  `Chunklen` int(255) NOT NULL default '0',
  PRIMARY KEY  (`ChunkNum`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 ;");
	mysql_query("CREATE TABLE IF NOT EXISTS `$value-s-prefixes` (
  `ID` int(255) NOT NULL auto_increment,
  `Hostkey` varchar(8) NOT NULL,
  `AddChunkNum` varchar(8) NOT NULL,
  `Prefix` varchar(255) NOT NULL,
  `FullHash` varchar(70) NOT NULL,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 ;");
	}
//Check timeout files writable
if(file_put_contents("testfile.dat","TEST PRE-USE PHPGSB ".time())
	unlink("testfile.dat");
else
	echo "<span style='color:red;font-weight:bold;'>ERROR: THIS DIRECTORY IS NOT WRITABLE, CHMOD to 775 or 777</span>";	
?>