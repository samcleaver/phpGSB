<?php
/**
 * phpGSB - PHP Google Safe Browsing Implementation
 * --> Storage Interface
 * 
 * Requires: PHP version 5+
 * 
 * @category Anti-Spam
 * @package  PHPGSB
 * @author   Sam Cleaver <cleaver.sam@gmail.com>
 * @license  New BSD License (see LICENSE)
 * @link     https://github.com/Beaver6813/phpGSB
 */
interface phpGSB_Storage_Adapter {
    const ERROR_DUPLICATE = 1;
    
    public function getAdapter();
    
    public function __construct($options);
    public function close();
    public function setTransactions($transactions);
    public function startTransaction();
    public function commitTransaction();
    public function rollbackTransaction();
    public function setConfig($key, $value);
    public function getConfig($key);
    public function getListRanges($listnames, $chunktypes = array("a", "s"));
    public function deleteListRanges($listname, $rangearray, $chunktype);
    public function resetLists($listnames, $chunktypes = array("a", "s"));
    public function saveChunk($listname, $type, $chunknum, $chunklen, $chunkdata);
    
}
?>