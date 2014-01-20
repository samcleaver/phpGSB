<?php
/**
 * phpGSB - PHP Google Safe Browsing Implementation
 * --> MySQL Adapter
 * 
 * Requires: PHP version 5+
 * 
 * @category Anti-Spam
 * @package  PHPGSB
 * @author   Sam Cleaver <cleaver.sam@gmail.com>
 * @license  New BSD License (see LICENSE)
 * @link     https://github.com/Beaver6813/phpGSB
 */

class phpGSB_Storage implements phpGSB_Storage_Adapter {
    /*
     * @var bool|MySQLi Object representing the MySQL connection
     */
    private $_dbh = false;
    /*
     * @var bool Are MySQL transactions enabled? (It is highly recommended they are.)
     */
    private $_transenabled = true;    
    
    /*
     * Return the name of the current Adapter (mySQL)
     * @return string
     */
    public function getAdapter() {
        return "MySQL";
    }
    
    /*
     * Constructor, setup DB connection if given information
     * @param array $useroptions Database options
     * @return void
     */
    public function __construct($useroptions) {
        $defaults = array("database" => false, "username" => false, "password" => false, "host" => "localhost", "port" => false);
        $options = array_merge($defaults, $useroptions);
        if($options['database']&&$options['username'])
            $this->dbConnect($options['database'],$options['username'],$options['password'],$options['host'],$options['port']);
    }
    
    /*
     * Destructor, cleans up parent class and closes database connection
     * @return void
     */
    public function __destruct() {
        //Close the database connection (if its open)
        if($this->_dbh) {
            $this->_dbh = null;
        }
    }
    
    /*
     * Convenience function to call destructor
     * @return void
     */
    public function close() {
        $this->__destruct();
    }
    
    /*
     * Connect to the MySQL database. Uses the newer MySQLi extension.
     * @param bool|string $database Database Name
     * @param bool|string $username Database Username
     * @param bool|string $password Database Password
     * @param bool|string $host Database Host
     * @return void
     */
    public function dbConnect($database,$username,$password,$host="localhost",$port=false)
        {
        //Initiate connection
        $dsn = "mysql:host=$host;dbname=$database";
        if($port)
            $dsn .= ";port=$port";
        
        try {
            $this->_dbh = new phpGSB_PDO($dsn, $username, $password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
        } catch (PDOException $e) {
            throw new phpGSBException('Could not connect to db: '.
                    $e->getMessage(), $e->getCode());
        }
        }
    
    /*
     * Ensure the required tables exist in the database
     * @param array $listnames An array of listnames
     * @param array $chunktype An array of desired chunktypes s (sub) / a (add)
     * @return void
     */
    public function installCheck($listnames, $chunktypes = array("a", "s")) {
        //Build array of tables to check
        $checkarray = array("config" => array("Type" => "config"));
        foreach($listnames as $name) {
            foreach($chunktypes as $type) {
                $checkarray[$name.'-'.$type.'-hashes'] = array("Type" => "hashes", "CType" => $type);
                $checkarray[$name.'-'.$type.'-index'] = array("Type" => "index", "CType" => $type);
            }
        }
        $existcheck = $this->_dbh->checkTables($checkarray);
        //Now loop over the results and create if necessary
        foreach($existcheck as $key => $value) {
            if(!$value['Exists']) {
                switch($value['Type']) {
                    case 'config':
                        $this->_dbh->exec('CREATE TABLE `'.$key.'` (
                                `Key` varchar(255) NOT NULL,
                                `Value` varchar(255) NOT NULL,
                                PRIMARY KEY (`Key`)
                              ) ENGINE=InnoDB DEFAULT CHARSET=ascii;');
                    break;
                    case 'hashes':
                        $sql = 'CREATE TABLE `'.$key.'` (
                                `ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
                                `Parent` binary(4) NOT NULL,
                                `Chunknum` int(10) unsigned NOT NULL,';
                        if($value['CType'] == 's')
                            $sql .= '`AddChunknum` int(10) unsigned NOT NULL,';
                        $sql .= '`Hash` binary(4) NOT NULL,
                                `Children` tinyint(3) unsigned NOT NULL,
                                `FullHash` varbinary(32) NOT NULL,
                                PRIMARY KEY (`ID`),
                                KEY `Parent` (`Parent`),
                                KEY `Hash` (`Hash`),
                                KEY `Chunknum` (`Chunknum`)
                              ) ENGINE=InnoDB DEFAULT CHARSET=binary AUTO_INCREMENT=1;';
                        $this->_dbh->exec($sql);
                    break;
                    case 'index':
                         $this->_dbh->exec('CREATE TABLE `'.$key.'` (
                                `Chunknum` int(10) unsigned NOT NULL,
                                `Chunklen` smallint(6) unsigned NOT NULL DEFAULT \'0\',
                                PRIMARY KEY (`Chunknum`)
                              ) ENGINE=InnoDB DEFAULT CHARSET=binary;');                       
                    break;
                }
            }
        }
    }
    
    /*
     * Turn transactions on or off, if they are turned off then unexpected
     * results may occur when errors occur.
     * @param bool $transactions
     * @return void
     */
    public function setTransactions($transactions) {
        $this->_transenabled = $transactions;
    }
    
    /*
     * Start a MySQL transaction
     * @return void
     */
    public function startTransaction() {
        if($this->_transenabled&&!$this->_dbh->inTransaction()) {
            $this->_dbh->beginTransaction();
        }
    } 
    /*
     * Commit a MySQL transaction
     * @return void
     */
    public function commitTransaction() {
        if($this->_dbh->inTransaction()) {
            $this->_dbh->commit();
        }
    }
    
    /*
     * Rollback a MySQL transaction
     * @return void
     */
    public function rollbackTransaction() {
        if($this->_dbh->inTransaction()) {
            $this->_dbh->rollBack();
        }
    }
        
    /*
     * Set a configuration variable to config table
     * @param string $key
     * @param string $value
     * @return void
     */
    public function setConfig($key, $value) {
        //We prepare the statement with the key value already inserted this
        //should always be defined by the script internally so no escaping done
        $sth = $this->_dbh->prepare("INSERT INTO `config` (`Key`, `Value`) VALUES".
                " ('$key', :value) ON DUPLICATE KEY UPDATE `Value` = :value");
        $sth->execute(array(':value' => $value));
        $this->_configcache[$key] = $value;
    }
    
    /*
     * Get a configuration variable from config table
     * @param string $key
     * @return string 
     */
    public function getConfig($key) {
        if(isset($this->_configcache[$key]))
            return $this->_configcache[$key];
        else {
            $sth = $this->_dbh->prepare("SELECT `Value` FROM `config` WHERE `Key` = :key LIMIT 1");
            if($sth->execute(array(':key' => $key))) {
                $row = $sth->fetch();
                if($row)
                    $this->_configcache[$key] = $row[0];
                $sth->closeCursor();
                if(isset($this->_configcache[$key]))
                    return $this->_configcache[$key];
                else
                    return false;
            } else {
                $sth->closeCursor();
                throw new phpGSBException("getConfig Error: ".$this->_dbh->errorCode());
            }
        }
    }
    
    /*
     * Get the ranges of chunks in a list
     * @param array $listnames An array of listnames
     * @param array $chunktype An array of desired chunktypes s (sub) / a (add)
     * @return array An array of ranges
     */
    public function getListRanges($listnames, $chunktypes = array("a", "s")) {
        //Range MySQL Statement, its long but very efficient.
        //We're changing table names so can't use prepared statements for this.
        $sql = 'SELECT FirstInRange.ChunkNum as start_n,
            (SELECT ChunkNum
             FROM `%1$s-%2$s-index` as LastInRange
             WHERE LastInRange.ChunkNum > FirstInRange.ChunkNum
                AND  NOT EXISTS(SELECT * 
                 FROM `%1$s-%2$s-index` as NextInRange 
                 WHERE NextInRange.ChunkNum = LastInRange.ChunkNum + 1)
             ORDER BY ChunkNum asc LIMIT 1) as end_n            
            FROM `%1$s-%2$s-index` as FirstInRange
               WHERE not exists(SELECT * 
                 FROM `%1$s-%2$s-index` as PreviousInRange 
                 WHERE PreviousInRange.ChunkNum = FirstInRange.ChunkNum - 1);';
        $rangearray = array();
        foreach($listnames as $name) {
            $rangearray[$name] = array();
            foreach($chunktypes as $type) {
                $rangearray[$name][$type] = array();
                //Build SQL for list/type
                $csql = sprintf($sql, $name, $type);
                foreach($this->_dbh->query($csql) as $row) {
                    $rangearray[$name][$type][] = array($row[0], $row[1]);
                }
            }
        }
        return $rangearray;
    }
    /**
     * Delete a given set of ranges in a list for a certain type
     * @param array $rangearray An array of ranges to delete
     * @param char $chunktype The type of chunk s (sub) or a (add)
     * @return void
     */
    public function deleteListRanges($listname, $rangearray, $chunktype) {
        //Build initial where statement
        $buildwhere = array();
        foreach($rangearray as $value) {
            $buildwhere[] = "(main.Chunknum >= '{$value[0]}' AND main.Chunknum <= '{$value[1]}')";
        }
        $initwhere = implode(" OR ", $buildwhere);
        //Built initial where statement, lets delete!
        //First delete from index
        $deletedchunks = $this->_dbh->exec("DELETE main FROM `$listname-$chunktype-index` as main WHERE $initwhere");
        //Theres no point in proceeding if we didn't delete anything..
        if($deletedchunks > 0) {
            //Delete hashes that match chunknum
            $this->_dbh->exec("DELETE main FROM `$listname-$chunktype-hashes` as main WHERE $initwhere");
        }
    }
        
    /**
     * Resets the given lists in the database
     * @param array $listnames An array of listnames
     * @param array $chunktype An array of chunktypes s (sub) / a (add)
     * @return void
     */
    public function resetLists($listnames, $chunktypes = array("a", "s")) {
        //Reset tables for list
        $sth = $this->prepare("SELECT concat('TRUNCATE TABLE ', TABLE_NAME, ';') 
                                FROM INFORMATION_SCHEMA.TABLES 
                                WHERE TABLE_SCHEMA = :dbname AND
                                FIND_IN_SET(TABLE_NAME,:tablelist)");
        //Build list of tables to reset
        $tablelist = '';
        $i = 0;
        foreach($listnames as $name) {
            foreach($chunktypes as $type) {
                if($i > 0)
                    $tablelist .= ',';
                $tablelist .= $name.'-'.$type.'-hashes';
                $tablelist .= $name.'-'.$type.'-index';
                $i++;
            }
        }
        $sth->execute(array("dbname"=>$this->_dbh->getDBName(), "tablelist" => $tablelist));
    }
    
    /*
     * Saves a chunk to the database
     * @param   string $listname    List name that the chunk belongs to
     * @param   char    $type       Type of chunk to add (add or sub)
     * @param   integer $chunknum   The number/ID of the chunk being saved
     * @param   integer $chunklen   The length of the chunk in bytes
     * @param   array   $chunkdata  An array of chunk information  
     */
    public function saveChunk($listname, $type, $chunknum, $chunklen, $chunkdata) {
        $sthIndex = $this->_dbh->prepare("INSERT INTO `$listname-$type-index` (`Chunknum`, `Chunklen`) VALUES (:chunknum, :chunklen)");
        try {
            $sthIndex->execute(array(':chunknum' => $chunknum, ':chunklen' => $chunklen));
        } catch (PDOException $e) {
            throw new phpGSBException($e->getMessage()."|".$e->getCode(), phpGSB_Storage::ERROR_DUPLICATE);
        }
        
        if(!empty($chunkdata)) {
            if($type == 'a') {
                $statement = "INSERT INTO `$listname-a-hashes` (`ID`, `Parent`, `Chunknum`, `Hash`, `Children`, `FullHash`) VALUES ";
                $questiontemplate = '(NULL, ?, ?, ?, ?, \'\'),';
            } else {
                $statement = "INSERT INTO `$listname-s-hashes` (`ID`, `Parent`, `Chunknum`, `AddChunknum`, `Hash`, `Children`, `FullHash`) VALUES ";
                $questiontemplate = '(NULL, ?, ?, ?, ?, ?, \'\'),';
            }
            
            $hasharray = array();
            $hasharrayq = '';
            foreach($chunkdata as $value) {
                //We have a host, add its data to our list
                $hasharray[] = '';
                $hasharray[] = $chunknum;
                if($type == 's') 
                    $hasharray[] = $value['addchunk'];
                $hasharray[] = $value['host'];
                $hasharray[] = $value['count'];
                $hasharrayq .= $questiontemplate;
                //Do we have any prefixes to add?
                if($value['count'] > 0) {
                    foreach($value['prefixes'] as $subvalue) {
                        $hasharray[] = $value['host'];
                        $hasharray[] = $chunknum;
                        if($type == 's') 
                            $hasharray[] = $value['addchunk'];
                        $hasharray[] = $subvalue['prefix'];
                        $hasharray[] = 0;
                        $hasharrayq .= $questiontemplate;
                    }
                }
            }
            //Remove last comma from values
            $values = substr($hasharrayq, 0, -1);
            $sthHashes = $this->_dbh->prepare($statement.$values);
            try {
                $sthHashes->execute($hasharray);
            } catch (PDOException $e) {
                throw new phpGSBException($e->getMessage()."|".$e->getCode());
            }
        }
    }
    
}

class phpGSB_PDO extends PDO {

    protected $_config = array();

    protected $_connected = false;
    
    protected $_reconnectguard = 0;

    public function __construct($dsn, $username = null, $passwd = null, $options = null) {
        //Extract database name from dsn for later use
        $dsnmatches = array();
        $dsnfiltered = preg_match("/dbname=([a-zA-Z0-9-_]+)(?:;|$)/", $dsn, $dsnmatches);
        if($dsnfiltered!=1) {
            throw new phpGSBException("Could not extract db name from DSN string.");
        }
        //Save connection details for later
        $this->_config = array(
            'dsn' => $dsn,
            'dbname' => $dsnmatches[1],
            'user' => $username,
            'pass' => $passwd,
            'options' => $options
        );
        parent::__construct($dsn, $username, $passwd, $options);
    }
    
    public function getDBName() {
        return $this->_config['dbname'];
    }
    
    public function reconnect($e) {
        if(($e->getCode() == 2006 || !$this->_connected) && $this->_reconnectguard < 3) {
            //MySQL Server has gone away, attempt reconnection
            extract($this->_config);
            try {
                parent::__construct($dsn, $user, $pass, $options);
            } catch (PDOException $e) {
                //Couldn't reconnect, return false and set flag
                $this->_connected = false;
                return false;
            }
            //If and exception wasn't thrown then we're still here
            //We've reconnected
            $this->_reconnectguard++;
            return true;
        } else {
            //MySQL server hasn't gone away so something else has gone wrong, we
            //can't help.
            return false;
        }
    }
    
    public function checkTables($tablenames) {
        //Checks if a table exists, uses method compatible with ANSI standard
        $sth = $this->prepare('SELECT COUNT(*) FROM information_schema.tables 
                        WHERE table_schema = :dbname AND table_name = :tablename;');
        $tablename = '';
        $sth->bindParam(':dbname', $this->getDBName());      
        $sth->bindParam(':tablename', $tablename);
        
        //Traverses through the array using the keys as tablenames and adds an exist key to their sub-array
        foreach($tablenames as $key => $value) {
            $tablename = $key;
            $sth->execute();
            $row = $sth->fetch();
            if($row && $row[0] > 0)
                $tablenames[$key]['Exists'] = true;
            else
                $tablenames[$key]['Exists'] = false;
        }
        $sth->closeCursor();        
        return $tablenames;
    }
    
    public function prepare($statement, $driver_options = array()) {
        try {
            return parent::prepare($statement, $driver_options);
        } catch (PDOException $e) {
            if($this->reconnect($e)) {
                return $this->prepare($statement, $driver_options);
            } else {
                throw new phpGSBException($e->getMessage()."|".$e->getCode());
            }
        }
    }



    public function query($query) {
        try {
            return parent::query($query);
        } catch (PDOException $e) {
            if($this->reconnect($e)) {
                return $this->query($query);
            } else {
                throw new phpGSBException($e->getMessage()."|".$e->getCode());
            }
        }
    }

    public function exec($query) {
        try {
            return parent::exec($query);
        } catch (PDOException $e) {
            if($this->reconnect($e)) {
                return $this->exec($query);
            } else {
                throw new phpGSBException($e->getMessage()."|".$e->getCode());
            }
        }
    }
    
}