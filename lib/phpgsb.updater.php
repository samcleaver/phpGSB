<?php
/**
 * phpGSB - PHP Google Safe Browsing Implementation
 * --> Updating Functions
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
class phpGSB_Updater extends PHPGSB_Core {
    
    /*
     * The updater can automatically retry when a data download fails. This constant
     * defines how many times it'll retry in a run.
     */
    const RETRY_LIMIT = 3;
    
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
    
    /**
     * Runs a chunk update session
     * @return void  
     */
    public function runUpdate() {
        //We can only update if we have storage
        if($this->_storage) {
            $intimeout = $this->checkTimeout(self::DATA_REQ);
            if($intimeout == 0) {
                //Setup MAC keys
                $this->setupMAC();
                //We're allowed to run
                $retrycount = 0;
                $gotdata = 1;
                while($gotdata == 1 && $retrycount < self::RETRY_LIMIT) {
                    try {
                    $gotdata = $this->getData();
                    } catch (phpGSBException $e) {
                        $this->_logger->logMsg("Error retrieving/process data, retrying.");
                    }
                    $retrycount++;
                }
                if($retrycount == 3 && $gotdata != 2) {
                    $this->_logger->logMsg("Stuck continually requesting and re-starting request. Aborting.");
                }
            } else {
                $this->_logger->logMsg("Must wait another $intimeout seconds before updating again",
                                        phpGSB_Logger::LOG_CRAZY);
            }
        } else {
            throw new phpGSBException("Cannot Update, No Database Connection");
        }
    }
    
    /*
     * Does the main work updating. Requests the initial data for given list.
     * @return int 0 for aborted, 1 for retry requested, 2 for completed
     */
    private function getData() {
        $reqbody = $this->buildDataRequest();
        $buildopts = array(CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$reqbody);
        $this->_logger->logMsg("Requesting data from GSB server", phpGSB_Logger::LOG_INFO);
        $dataresult = $this->downloadData($this->_cdlurls['Downloads'], $buildopts, "data");
        if($dataresult) {
            $resplines = array();
            $dataprocessed = preg_match_all("/^(?:([a-zA-Z0-9]+):(.*)(?:\R))/m", $dataresult[1], $resplines, PREG_SET_ORDER);
            if($dataprocessed > 0) {
                //We have some data to look at!
                //First check the overall MAC if we're using it
                if($this->_usemac) {
                   //The MAC key should be in the first line, lets check if its valid
                   if($resplines[0][1] == 'm') {
                       //Lets check if the MAC is valid!
                       $this->_logger->logMsg("Checking received response MAC..", phpGSB_Logger::LOG_CRAZY);
                       $datatovalidate = str_replace($resplines[0][0], '', $dataresult[1]);
                       //If its not valid then exit
                       if(!$this->validateMAC($resplines[0][2], $datatovalidate)) {
                            //Received invalid MAC, this shouldn't happen.
                            $this->_logger->logFatal("Received invalid MAC from server. Received: {$resplines[0][2]} for $datatovalidate");
                       }
                   } elseif($resplines[0][1] == 'e') {
                       if($resplines[0][2]=='pleaserekey') {
                           //Server asked us to request a new key. Lets do it.
                           $this->_logger->logMsg("Server requested rekey. Re-keying and re-submitting.");
                           $this->_cdlurls = $this->compileDLURLs();
                           $this->requestNewMAC();
                           return 1;                           
                       }
                   } else {
                       $this->_logger->logFatal("Expected a MAC, didn't receive one.");
                   }
                   unset($resplines[0]);
                }
                //If we're still here then either MAC was fine or not using MAC.
                $this->_storage->startTransaction();
                $timeout = 0;
                $currentlist = '';
                foreach($resplines as $value) {
                    $keyword = $value[1];
                    $data = $value[2];
                    switch($keyword) {
                        case 'n':
                            //Getting new timeout value, will set at end of successful transaction.
                            $timeout = $data;
                        break;
                        case 'i':
                            //Setting new current list
                            $currentlist = $data;
                        break;
                        case 'r':
                            if($data=='pleasereset') {
                                //Reset database (all lists)
                                $this->_storage->resetLists($this->_usinglists);
                                $this->_logger->logMsg("Received reset command from server. Resetting local database.");
                                return 1;
                            } else
                                $this->fatalRollback("Received reset keyword but not the pleasereset data.");
                        break;
                        case 'sd':
                        case 'ad':
                            //Delete a bunch of chunks
                            //Make ranges given into nice array (providing we have a list to work on)
                            $chunktype = ($keyword == 'sd' ? 's' : 'a');
                            $this->_logger->logMsg("Deleting range of chunks from $currentlist $chunktype ($data)", phpGSB_Logger::LOG_INFO);
                            if(!empty($currentlist)) {
                                $rangearray = $this->rangesToArray($data);
                                if(!empty($rangearray))
                                    $this->_storage->deleteListRanges($currentlist, $rangearray, $chunktype);
                                else
                                    $this->fatalRollback("Received $chunktype-chunk delete command but no ranges to delete.");
                            } else
                                $this->fatalRollback("Received $chunktype-chunk delete command but we haven't been given a list via the i keyword.");
                        break;
                        case 'u':
                            //Handle a chunk redirect (providing we have a list to allocate to)
                            if(!empty($currentlist)) {
                                $redirectdata = explode(",", $data, 2);
                                $mackey = false;
                                //If we're expecting a mac then decode and use it
                                if($this->_usemac) {
                                    if(count($redirectdata) == 2) {
                                        $mackey = $redirectdata[1];
                                    } else
                                        $this->fatalRollback("Received chunk redirect/data we haven't been given a list via the i keyword.");
                                }
                                //Hand off processing to processRedirect
                                try {
                                    $this->_logger->logMsg("Processing Redirect List...", phpGSB_Logger::LOG_INFO);
                                    $this->processRedirect("http://".$redirectdata[0], $currentlist, $mackey);
                                } catch (phpGSBException $e) {
                                    $this->fatalRollback("Error processing a redirect. Must discard entire response. (".$e->getMessage().")");
                                }
                            } else
                                $this->fatalRollback("Received chunk redirect/data we haven't been given a list via the i keyword.");
                            
                        break;
                    } 
                }
                //If we're still here then we presume it went well, commit!
                $this->_logger->logMsg("Data processing complete. Committing to storage.", phpGSB_Logger::LOG_INFO);
                try {
                    $this->_storage->commitTransaction();
                    $this->_logger->logMsg("Commit Successful!", phpGSB_Logger::LOG_INFO);
                    $this->_logger->logMsg("Set next request timeout to: $timeout", phpGSB_Logger::LOG_INFO);      
                    $this->setTimeout(self::DATA_REQ, $timeout);
                } catch (PDOException $e) {
                    $this->fatalRollback("Error committing to storage. Aborting. (".$e->getMessage().")");
                }
            } else {
                $this->_logger->logFatal("Received data from GSB but couldn't decode it.");
            }
        }
    }
    
    /**
     * Processes a redirect supplied by a data response
     * @param string $redirecturl
     * @param bool|string $mackey
     * @return void
     */
    private function processRedirect($redirecturl, $currentlist, $mackey) {
        $this->_logger->logMsg("Downloading redirect data...", phpGSB_Logger::LOG_CRAZY);
        $dataresult = $this->downloadData($redirecturl, false, "data");
        if($mackey) {
            $this->_logger->logMsg("Checking MAC of redirect data..", phpGSB_Logger::LOG_CRAZY);
            if(!$this->validateMAC($mackey, $dataresult[1])) {
                //Received invalid MAC, this shouldn't happen.
                $this->_logger->logFatal("Received invalid MAC from server. Received: {$mackey} for {$dataresult[1]}");
           }
        }
        //Lets start parsing!
        $workingdata = $dataresult[1];
        
        $lastlen = 0;
        while(strlen($workingdata)>0 && strlen($workingdata) != $lastlen) {
            $lastlen = strlen($workingdata);
            $dataparts = explode("\n", $workingdata, 2);
            $header = explode(":", $dataparts[0], 4);
            //Normalize the data for parsing
            $chunktype = $header[0];
            $chunknum = $header[1];
            $hashlen = $header[2];
            $chunklen = $header[3];
            //Remove the retrieved header from working data
            $workingdata = $dataparts[1];
            //Substr reads a character as a byte which is exactly what we want.
            $chunkdata = substr($workingdata, 0, $chunklen);
            //Remove the retrieved chunk from working data
            $workingdata = substr($workingdata, $chunklen);
            //Parse the chunk into a nice array
            if($chunktype == 'a') {
                $parsedchunk = $this->parseAddChunk($chunkdata, $hashlen);
                $this->_logger->logMsg("Add chunk $chunknum parsed successfully. Sending to storage.", phpGSB_Logger::LOG_CRAZY);
            } elseif($chunktype == 's') {
                $parsedchunk = $this->parseSubChunk($chunkdata, $hashlen);
                $this->_logger->logMsg("Sub chunk $chunknum parsed successfully. Sending to storage.", phpGSB_Logger::LOG_CRAZY);
            } else
                $this->fatalRollback("Received chunkdata with invalid chunk type ($chunktype).");
            
            //If we're still here then save the chunk
            try {
                $this->_storage->saveChunk($currentlist, $chunktype, $chunknum, $chunklen, $parsedchunk);
            } catch(phpGSBException $e) {
                //If its a duplicate thats fine
                if($e->getCode() == phpGSB_Storage::ERROR_DUPLICATE)
                    $this->_logger->logMsg("Didn't save chunk $chunknum from $currentlist $chunktype as it already existed.", phpGSB_Logger::LOG_INFO);
                else
                    throw new phpGSBException($e->getMessage(), $e->getCode());
            }
        }
    }
    
    /**
     * Parses a sub chunk given the raw data
     * @param binary $chunkdata
     * @param int $hashlen Length of prefix hashes
     * @return array
     * @todo add more error checking
     */
    private function parseSubChunk($chunkdata, $hashlen) {
        $parsedchunk = array();
        for($i = 0; strlen($chunkdata) > 0; $i++) {
            //Unpack the count
            $tempunpack = unpack("C1c", substr($chunkdata, 4, 1));

            $parsedchunk[$i]['host'] = substr($chunkdata, 0, 4);
            $parsedchunk[$i]['count'] = $tempunpack['c'];
            $parsedchunk[$i]['addchunk'] = 0;
            //Remove hostkey/count from chunkdata
            $chunkdata = substr($chunkdata, 5);
            if($parsedchunk[$i]['count'] == 0) {
                //A count of 0 is a special condition
                $tempunpack = unpack("N1add", $chunkdata);
                $parsedchunk[$i]['addchunk'] = $tempunpack['add'];
                $chunkdata = substr($chunkdata, 4);
            } else {
                $parsedchunk[$i]['prefixes'] = array();
                for($j = 0; $j < $parsedchunk[$i]['count']; $j++) {
                    //Unpack an addchunknum and prefix
                    //Because we're strictly following the specs, we can't just assume
                    //that the prefix will be 4 bytes so can't use an unsigned long.
                    $tempunpack = unpack("N1add", $chunkdata);
                    $parsedchunk[$i]['prefixes'][] = array("addchunk" => $tempunpack['add'], "prefix" => substr($chunkdata, 4, $hashlen));
                    //Remove the addchunknum/prefix from chunkdata
                    $chunkdata = substr($chunkdata, 4 + $hashlen);
                }
            }
        }
        return $parsedchunk;
    }
    
    /**
     * Parses an add chunk given the raw data
     * @param binary $chunkdata
     * @param int $hashlen Length of prefix hashes
     * @return array
     * @todo add more error checking
     */
    private function parseAddChunk($chunkdata, $hashlen) {
        $parsedchunk = array();
        
        for($i = 0; strlen($chunkdata) > 0; $i++) {
            //Unpack the count
            $tempunpack = unpack("C1c", substr($chunkdata, 4, 1));

            $parsedchunk[$i]['host'] = substr($chunkdata, 0, 4);
            $parsedchunk[$i]['count'] = $tempunpack['c'];
            //Remove hostkey/count from chunkdata
            $chunkdata = substr($chunkdata, 5);
            if($parsedchunk[$i]['count'] > 0) {
                $parsedchunk[$i]['prefixes'] = array();
                for($j = 0; $j < $parsedchunk[$i]['count']; $j++) {
                    $parsedchunk[$i]['prefixes'][] = substr($chunkdata, 0, $hashlen);
                    //Remove the addchunknum/prefix from chunkdata
                    $chunkdata = substr($chunkdata, $hashlen);
                }
            }
        }
        return $parsedchunk;
    }
    
    /**
     * Rollsback the current transaction and calls the logFatal method of logger
     * @param string $error
     * @return void
     */
    private function fatalRollback($error) {
        $this->_storage->rollbackTransaction();
        $this->_logger->logFatal($error);
    }
    
    /**
     * Converts a range string into a nice array
     * @param string Double delimited string (i.e. 1234-5678,3456-7890,9593
     * @return array
     */
    private function rangesToArray($ranges) {
        $outputranges = array();
        $rangegroups = explode(',', $ranges);
        if(!empty($rangegroups[0])) {
            $i = 0;
            foreach($rangegroups as $value) {
                $rangeparts = explode('-', $value);
                //Define lower part of range
                $outputranges[$i][] = preg_replace("/[^0-9]/", "", $rangeparts[0]);
                //Define upper part of range, if its a single value then just duplicate lower
                if(count($rangeparts) == 1)
                    $outputranges[$i][] = preg_replace("/[^0-9]/", "", $rangeparts[0]);
                else
                    $outputranges[$i][] = preg_replace("/[^0-9]/", "", $rangeparts[1]);
                $i++;
            }
        }
        return $outputranges;
    }
    
    /*
     * Builds the data request body
     * @param void
     * @return string
     */
    private function buildDataRequest() {
        $this->_logger->logMsg("Building List Ranges", phpGSB_Logger::LOG_CRAZY);
        $listranges = $this->_storage->getListRanges($this->_usinglists);
        $request = '';
        foreach($listranges as $listname => $chunkranges) {
            $request .= $listname.';';
            $typecount = 0;
            foreach($chunkranges as $chunktype => $ranges) {
                if(!empty($ranges)) {
                    if($typecount > 0)
                        $request .= ':';
                    $request .= $chunktype.':';
                    $rangecount = 0;
                    foreach($ranges as $range) {
                        if($rangecount > 0)
                            $request .= ',';
                        $request .= implode("-", $range);
                        $rangecount++;
                    }
                    $typecount++;
                }
            }
            if($typecount > 0 && $this->_usemac)
                $request .= ':mac';
            else if($this->_usemac)
                $request .= 'mac';
            $request .= "\n";
        }
        $this->_logger->logMsg("Request body for GSB: ".$request, phpGSB_Logger::LOG_CRAZY);
        return $request;
    }
    
}