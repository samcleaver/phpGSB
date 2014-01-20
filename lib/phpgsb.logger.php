<?php
/**
 * phpGSB - PHP Google Safe Browsing Implementation
 * --> Logging and Exception Functions
 * 
 * Requires: PHP version 5+
 * 
 * @category Anti-Spam
 * @package  PHPGSB
 * @author   Sam Cleaver <cleaver.sam@gmail.com>
 * @license  New BSD License (see LICENSE)
 * @link     https://github.com/Beaver6813/phpGSB
 */

class phpGSBException extends Exception
{
    public function __construct($message, $code = 0) {
        parent::__construct($message, $code);
    }    
}

class phpGSB_Logger {
    //Define logging levels
    const LOG_NONE = 0;
    const LOG_ERROR = 1;
    const LOG_INFO = 2;
    const LOG_CRAZY = 3;
    
    //Log of messages produced whilst running
    protected $_log            = array();
    //Email address to send any critical information to
    private $_adminemail    = "";
    //How verbose should phpGSB be? 0 = Silent, 3 = Fully verbose
    private $_logginglevel    = self::LOG_INFO;
    //Should phpGSB output the log as it is going?
    private $_outputlog  = true;
    
    /*
     * Constructor, set default logging level and whether to output
     * @return void
     */
    public function __construct($logginglevel = self::LOG_INFO, $outputlog = false) {
         //Logging settings
        if($outputlog)
            $this->verbose();
        else
            $this->silent();
        
        $this->setLoggingLevel($logginglevel);
    }
    
    /*
     * Set error/admin email address incase of fatal errors and resets
     * @return void
     */
    public function setErrorEmail($email) {
        $this->_adminemail = $email;
    }
    
    /*
     * Sets the verbosity of the application
     * @param int $loglevel
     * @return void
     */
    public function setLoggingLevel($loglevel) {
        $this->_logginglevel = $loglevel;
    }
    /*
     * Turns off outputting log messages
     * @return void
     */
    public function silent() {
        $this->_outputlog = false;
    }
    /*
     * Turns on outputting log messages
     * @return void 
     */
    public function verbose() {
        $this->_outputlog = true;
    }
    
    /*
     * Logs message and outputs depending on settings.
     * @param mixed $msg
     * @param int $loglevel
     * @return void
     */
    public function logMsg($msg, $loglevel = self::LOG_INFO) {
        //Do we care about this log level?
        if($this->_logginglevel >= $loglevel) {
            //Yes we do, append to array
            $this->_log[] = array($msg, $loglevel);
            //Do we want to output?
            if($this->_outputlog) {
               $this->outputLogLine($msg, $loglevel);
            }
        }
    }
    
    /*
     * Logs fatal error and throws exception.
     * @param mixed $msg
     * @param int $loglevel
     * @return void
     */
    public function logFatal($msg) {
        //Do we care about this log level?
        $loglevel = self::LOG_ERROR;
        if($this->_logginglevel >= $loglevel) {
            //Yes we do, append to array
            $this->_log[] = array($msg, $loglevel);
            //Do we want to output?
            if($this->_outputlog) {
               $this->outputLogLine($msg, $loglevel);
            }
            //Throw new phpGSBException
            throw new phpGSBException($msg, $loglevel);
        }
    }
        
    /*
     * Outputs log line to STDOUT (console/browser).
     * @param mixed $msg
     * @param int $loglevel
     * @return void
     */
    protected function outputLogLine($msg, $loglevel) {
        //Convert log level to string
        $logdesc = '';
        switch($loglevel) {
            case self::LOG_ERROR:
                $logdesc = "ERROR";
            break;
            case self::LOG_INFO:
                $logdesc = "INFO";
            break;
            case self::LOG_CRAZY:
                $logdesc = "CRAZY";
            break;
            default:
                $logdesc = "???";
            break;
        }
        //Output log
        echo "phpGSB [".date("c")."] $logdesc ".$msg."\n";
    }
    
    
}