<?php
/**
 * phpGSB - PHP Google Safe Browsing Implementation
 * --> URL Lookup Functions
 * 
 * Requires: PHP version 5+
 * 
 * @category Anti-Spam
 * @package  PHPGSB
 * @author   Sam Cleaver <cleaver.sam@gmail.com>
 * @license  New BSD License (see LICENSE)
 * @link     https://github.com/Beaver6813/phpGSB
 */
require_once("phpgsb.core.php");
require_once("phpgsb.canonicalizer.php");
class phpGSB_Lookup extends PHPGSB_Core {
    
    /**
     * Accepts logging level and whether to output log
     * @param string $logginglevel Sets the logging level (0 - 3, 3 being most verbose)
     * @param bool      $outputlog Sets whether to output the log or not
     * @return void
     */
    public function __construct($logginglevel=phpGSB_Logger::LOG_INFO, $outputlog=false) {
        parent::__construct($logginglevel, $outputlog);
    }
    
    /*
     * Destructor, calls parent destructor and unsets variables
     * @return void
     */
    public function __destruct() {
        parent::__destruct();
    }
    
    /*
     * 
     */
    public function doLookup($url) {
        $processedurl = new phpGSB_Canonicalizer($url);
    }
    
}