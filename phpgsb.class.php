<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Version 0.2.4
Released under New BSD License (see LICENSE)
Copyright (c) 2010-2012, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.
*/
ob_start();
class phpGSB
	{
	var $apikey 	= "";	
	var $version 	= "0.2";
	var $realversion= "0.2.4";
	//DO NOT CHANGE API VERSION
	var $apiversion	= "2.2";
	
	var $ob			= "";
	var $adminemail	= "";
	var $usinglists = array('googpub-phish-shavar','goog-malware-shavar');
	var $mainlist	= array();
	var $verbose	= true;
	var $transtarted= false;
	var $transenabled=true;
	var $pingfilepath=""; //This is the path used to store the ping/last update files. (Must inc. trailing slash)
	//GENERIC FUNCTIONS (USED BY BOTH LOOKUP AND UPDATER)
	/*Automatically connect to database on calling class*/
	function phpGSB($database=false,$username=false,$password=false,$host="localhost",$verbose=true)
		{
		if(!$verbose)
			$this->silent();
		$this->outputmsg("phpGSB Loaded");
		if($database&&$username)	
			$this->dbConnect($database,$username,$password,$host);
		}
	function close()
		{
		mysql_close();	
		$this->outputmsg("Closing phpGSB. (Peak Memory: ".(round(memory_get_peak_usage()/1048576,3))."MB)");
		}
	function silent()
		{
		$this->verbose = false;	
		}
	function trans_disable()
		{
		$this->transenabled = false;	
		}
	function trans_enable()
		{
		$this->transenabled = true;	
		}
	function trans_begin()
		{
		if($this->transenabled)
			{
			$this->transtarted = true;
			$this->outputmsg("Begin MySQL Transaction");
			mysql_query("BEGIN");
			}
		}
	function trans_commit()
		{
		if($this->transtarted&&mysql_ping()&&$this->transenabled)
			{
			$this->transtarted = false;
			$this->outputmsg("Comitting Transaction");
			mysql_query("COMMIT");
			}
		}
	function trans_rollback()
		{
		if($this->transtarted&&mysql_ping()&&$this->transenabled)
			{
			$this->transtarted = false;
			$this->outputmsg("Rolling Back Transaction");
			mysql_query("ROLLBACK");
			}
		}
	/*Function to output messages, used instead of echo,
	  will make it easier to have a verbose switch in later
	  releases*/
	function outputmsg($msg)
		{
		if($this->verbose)
			{
			echo $msg.'...<br/>';
			$this->ob .= ob_get_contents();
			ob_flush();
			}
		}
	/*Function to output errors, used instead of echo,
	  will make it easier to have a verbose switch in later
	  releases*/	
	function fatalerror($msg)
		{
		if($this->verbose)
			{
			print_r($msg);
			echo '...<br/>';
			$this->ob .= ob_get_contents();
			ob_end_flush();
			}
		$this->trans_rollback();
		die();
		}
	/*Wrapper to connect to database. Simples.*/
	function dbConnect($database,$username,$password,$host="localhost")
		{
		$link = mysql_connect($host, $username, $password);
		if (!$link) {
			$this->fatalerror('Could not connect: ' . mysql_error());
		}
		$this->outputmsg('Connected successfully to database server');
		$db_selected = mysql_select_db($database, $link);
		if (!$db_selected) {
			$this->fatalerror('Can\'t use $database : ' . mysql_error());
		}
		$this->outputmsg('Connected to database successfully');		
		}
	/*Simple logic function to calculate timeout
	  based on the number of previous errors*/			
	function calc($errors)
		{
		//According to Developer Guide Formula 
		if($errors==1)
			{
			//According to Developer Guide (1st error, wait a minute)
			return 60;			
			}
		elseif($errors>5)
			{
			//According to Developer Guide (Above 5 errors check every 4 hours)
			return 28800;
			}
		else
			{
			//According to Developer Guide we simply double up our timeout each time and use formula:
			//(Adapted to be relative to errors) ( ((2^$errors) * 7.5) * (decimalrand(0,1) + 1)) to produce
			// a result between: 120min-240min for example
			return floor((pow(2,$errors) * 7.5) * ((rand(0,1000)/1000) + 1));		
			}
		}
	/*Writes backoff timeouts, uses calc() to
	  calculate timeouts and then writes to file
	  for next check*/
	function Backoff($errdata=false,$type)
		{
		if($type=="data")
			$file = 'nextcheck.dat';
		else
			$file = 'nextcheckl.dat';
		$curstatus = explode('||',file_get_contents($this->pingfilepath.$file));
		$curstatus[1] = $curstatus[1] + 1;
		$seconds = $this->calc($curstatus[1]);
		$until = time()+$seconds.'||'.$curstatus[1];
		file_put_contents($this->pingfilepath.$file,$until);
		$this->fatalerror(array("Invalid Response... Backing Off",$errdata));	
		}
	/*Writes timeout from valid requests to nextcheck file*/
	function setTimeout($seconds)
		{
		$curstatus = explode('||',file_get_contents($this->pingfilepath.'nextcheck.dat'));
		$until = time()+$seconds.'||'.$curstatus[1];
		file_put_contents($this->pingfilepath.'nextcheck.dat',$until);	
		}
	/*Checks timeout in timeout files (usually performed at the
	  start of script)*/
	function checkTimeout($type)
		{
		if($type=="data")
			$file = 'nextcheck.dat';
		else
			$file = 'nextcheckl.dat';
		$curstatus = explode('||',file_get_contents($this->pingfilepath.$file));
		if(time()<$curstatus[0])
			{
			$this->fatalerror("Must wait another ".($curstatus[0]-time()). " seconds before another request");
			}
		else
			$this->outputmsg("Allowed to request");
		}
	/*Function downloads from URL's, POST data can be
	  passed via $options. $followbackoff indicates
	  whether to follow backoff procedures or not*/	
	function googleDownloader($url,$options,$followbackoff=false)
		{
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		
		if(is_array($options))
			curl_setopt_array($ch, $options);
		
		$data = curl_exec($ch);
		$info = curl_getinfo($ch);
		curl_close($ch);
		if($followbackoff&&$info['http_code']>299)
			{
			$this->Backoff($info,$followbackoff);
			}
		return array($info,$data);		
		}	
	//UPDATER FUNCTIONS
	/*Resets lists database, only called if GSB issues r:resetdatabase*/
	function resetDatabase()
		{
		//Lord knows why they would EVER issue this request!
		if(!empty($this->adminemail))
			mail($this->adminemail,'Reset Database Request Issued','For some crazy unknown reason GSB requested a database reset at '.time());
		foreach($this->usinglists as $value)
			{
			mysql_query("TRUNCATE TABLE `$value-s-index`");	
			mysql_query("TRUNCATE TABLE `$value-s-hosts`");	
			mysql_query("TRUNCATE TABLE `$value-s-prefixes`");	
			mysql_query("TRUNCATE TABLE `$value-a-index`");	
			mysql_query("TRUNCATE TABLE `$value-a-hosts`");	
			mysql_query("TRUNCATE TABLE `$value-a-prefixes`");	
			}
		}
	/*Processes data recieved from a GSB data request into a managable array*/
	function processChunks($fulldata,$listname)
		{
		$subarray = array();
		$addarray = array();
		$loaddata = trim($fulldata);
		$clonedata = $loaddata;
		while(strlen($clonedata)>0)
			{
			$splithead = explode("\n",$clonedata,2);
			$chunkinfo = explode(':',$splithead[0]);
			$type = $chunkinfo[0];
			$chunknum = $chunkinfo[1];
			$hashlen = $chunkinfo[2];
			$chunklen = $chunkinfo[3];
			if($chunklen>0)
				{
				$tmparray = array();
				//Convert to hex for easy processing
				//First get chunkdata according to length
				$chunkdata = bin2hex(substr($splithead[1],0,$chunklen));
				if($type=='a')
					{
					$maini = 0;
					while(strlen($chunkdata)>0)
						{
						$tmparray[$maini]['HOSTKEY'] = substr($chunkdata, 0, 8); 
						$tmparray[$maini]['COUNT'] = substr($chunkdata, 8, 2);
						$chunkdata = substr($chunkdata,10);
						$realcount = hexdec($tmparray[$maini]['COUNT']);
						if($realcount>0)
							{
							for ($i = 0; $i < $realcount; $i++) { 
							$tmparray[$maini]['PAIRS'][$i]['PREFIX'] = substr($chunkdata, 0, ($hashlen*2));
							$chunkdata = substr($chunkdata,(($hashlen*2)));
							}		
							}
						elseif($realcount<0)
							{
							$this->fatalerror(array("Decoding Error, Somethings gone wrong!",$tmparray[$maini]));	
							}
						$maini++;
						}
					$addarray['CHUNKNUM'] = $chunknum;
					$addarray['HASHLEN'] = $hashlen;
					$addarray['CHUNKLEN'] = $chunklen;
					$addarray['REAL'] = $tmparray;
					$this->saveChunkPart($addarray,"ADD",$listname);
					unset($addarray);			
					}
				elseif($type=='s')
					{
					$maini = 0;
					while(strlen($chunkdata)>0)
						{
						$tmparray[$maini]['HOSTKEY'] = substr($chunkdata, 0, 8); 
						$tmparray[$maini]['COUNT'] = substr($chunkdata, 8, 2);
						$chunkdata = substr($chunkdata,10);
						$realcount = hexdec($tmparray[$maini]['COUNT']);
						if($realcount>0)
							{
							for ($i = 0; $i < $realcount; $i++) { 
							$tmparray[$maini]['PAIRS'][$i]['ADDCHUNKNUM'] = substr($chunkdata, 0, 8);
							$tmparray[$maini]['PAIRS'][$i]['PREFIX'] = substr($chunkdata, 8, ($hashlen*2));
							$chunkdata = substr($chunkdata,(($hashlen*2)+8));
							}		
							}
						elseif($realcount==0)
							{
							$tmparray[$maini]['PAIRS'][0]['ADDCHUNKNUM'] = substr($chunkdata, 0, 8);
							$chunkdata = substr($chunkdata, 8);
							}
						else
							{
							$this->fatalerror(array("Decoding Error, Somethings gone wrong!",$tmparray[$maini]));				
							}
						$maini++;
						}	
					$subarray['CHUNKNUM'] = $chunknum;
					$subarray['HASHLEN'] = $hashlen;
					$subarray['CHUNKLEN'] = $chunklen;
					$subarray['REAL'] = $tmparray;
					$this->saveChunkPart($subarray,"SUB",$listname);
					unset($subarray);
					}
				else
					{
					$this->outputmsg("DISCARDED CHUNKNUM: $chunknum (Had no valid label)");
					}
				}
			else
				{
				//No ChunkData, Still Insert	
				if($type=='a')
					{
					$addarray['CHUNKNUM'] = $chunknum;
					$addarray['HASHLEN'] = $hashlen;
					$addarray['CHUNKLEN'] = $chunklen;
					$this->saveChunkPart($addarray,"ADD",$listname);
					unset($addarray);
					}
				elseif($type=='s')
					{
					$subarray['CHUNKNUM'] = $chunknum;
					$subarray['HASHLEN'] = $hashlen;
					$subarray['CHUNKLEN'] = $chunklen;	
					$this->saveChunkPart($subarray,"SUB",$listname);
					unset($subarray);
					}
				else
					{
					$this->outputmsg("DISCARDED CHUNKNUM: $chunknum (Empty)");
					}
				}
			$clonedata = substr($splithead[1],$chunklen);
			}
		return true;
		}
	/*Saves processed data to the MySQL database*/	
	function saveChunkPart($data,$type,$listname)
		{
		$listname = trim($listname);
		  //Check what type of data it is...
		  $buildindex = array();
		  $buildhost = array();
		  $buildpairs = array();
		  if($type=="SUB")
		  	{
			 $value = $data;
			  if(!isset($this->mainlist['s'][$listname][$value['CHUNKNUM']]))
				  {
				  $this->mainlist['s'][$listname][$value['CHUNKNUM']] = true;
				  $buildindex[] = "('{$value['CHUNKNUM']}','{$value['CHUNKLEN']}')";
				  if($value['CHUNKLEN']>0)
					  {
					  foreach($value['REAL'] as $newkey=>$newvalue)
						  {
						  $buildhost[] = "('{$newvalue['HOSTKEY']}','{$value['CHUNKNUM']}','{$newvalue['COUNT']}','')";
						  if(isset($newvalue['PAIRS'])&&count($newvalue['PAIRS'])>0)
							  {
							  foreach($newvalue['PAIRS'] as $innerkey=>$innervalue)
								  {
								  if( isset($innervalue['PREFIX']) ) {
										$buildpairs[] = "('{$newvalue['HOSTKEY']}','{$innervalue['ADDCHUNKNUM']}','{$innervalue['PREFIX']}','')";
									} else {
										$buildpairs[] = "('{$newvalue['HOSTKEY']}','{$innervalue['ADDCHUNKNUM']}','','')";
										}
								  }				
							  }	
						  }	
					  }
				  }
			}
		else if($type=="ADD")
			{
		  //Then lets insert add data
		  $value = $data;
			  if(!isset($this->mainlist['a'][$listname][$value['CHUNKNUM']]))
				  {
				  $this->mainlist['a'][$listname][$value['CHUNKNUM']] = true;
				  $buildindex[] = "('{$value['CHUNKNUM']}','{$value['CHUNKLEN']}')";
				  if($value['CHUNKLEN']>0)
					  {
					  foreach($value['REAL'] as $newkey=>$newvalue)
						  {
						  $buildhost[] = "('{$newvalue['HOSTKEY']}','{$value['CHUNKNUM']}','{$newvalue['COUNT']}','')";
						  if(isset($newvalue['PAIRS'])&&count($newvalue['PAIRS'])>0)
							  {
							  foreach($newvalue['PAIRS'] as $innerkey=>$innervalue)
								  {
									if( isset($innervalue['PREFIX']) ) {
								  $buildpairs[] = "('{$newvalue['HOSTKEY']}','{$innervalue['PREFIX']}','')";
									} else {
									$buildpairs[] = "('{$newvalue['HOSTKEY']}','','')";	
									}
								  }				
							  }	
						  }	
					  }
				  }
			}
		if(count($buildindex)>0)
			{
			if($type=="ADD")
				$listtype = 'a';
			elseif($type=="SUB")
				$listtype = 's';
			//Insert index value
			$indexinsert = implode(', ',$buildindex);
			$indexins = mysql_query("INSERT INTO `$listname-$listtype-index` (`ChunkNum`,`Chunklen`) VALUES $indexinsert;");
			$error = mysql_error();
			if($indexins)
				{
				if(count($buildhost)>0)
					{
					//Insert hostkeys index
					 $hostinsert = implode(', ',$buildhost);
					mysql_query("INSERT INTO `$listname-$listtype-hosts` (`Hostkey`,`Chunknum`,`Count`,`FullHash`) VALUES $hostinsert;");
					$error = mysql_error();
					if(!empty($error))
						$this->outputmsg("INSERTED $listname $type HOST KEYS ".mysql_error());
					}
				if(count($buildpairs)>0)
					{
					//Insert prefixes
					$pairinsert = implode(', ',$buildpairs);
					if($type=="ADD")
						mysql_query("INSERT INTO `$listname-$listtype-prefixes` (`Hostkey`,`Prefix`,`FullHash`) VALUES $pairinsert;");
					elseif($type=="SUB")
						mysql_query("INSERT INTO `$listname-$listtype-prefixes` (`Hostkey`,`AddChunkNum`,`Prefix`,`FullHash`) VALUES $pairinsert;");
					$error = mysql_error();
					if(!empty($error))
						$this->outputmsg("INSERTED $listname $type PREFIX HOST KEYS ".mysql_error());
					}
				}
			elseif(!empty($error))
				$this->outputmsg("COULD NOT SAVE $listname $type INDEXS ".mysql_error());
			}
		}	
	/*Get ranges of existing chunks from a requested list
	  and type (add [a] or sub [s] return them and set
	  mainlist to recieved for that chunk (prevent dupes)*/
	function getRanges($listname,$mode)
		{
		$checktable = $listname.'-'.$mode.'-index';	
		$results = mysql_query("SELECT ChunkNum FROM `$checktable` ORDER BY `ChunkNum` ASC");
		$ranges = array();
		$i = 0;
		while ($row = mysql_fetch_array($results, MYSQL_BOTH))
			{
			$this->mainlist[$mode][$listname][$row['ChunkNum']] = true;
			if($i==0)
				{
				$start = $row['ChunkNum'];
				$previous = $row['ChunkNum'];
				}
			else
				{
				$expected = $previous + 1;
				if($row['ChunkNum']!=$expected)
					{
					if($start==$previous)
						$ranges[] = $start;
					else
						$ranges[] = $start.'-'.$previous;
					$start = $row['ChunkNum'];
					}
				$previous = $row['ChunkNum'];
				}
			$i++;
			}
		if($start>0&&$previous>0)
			{
			if($start==$previous)
				$ranges[] = $start;
			else
				$ranges[] = $start.'-'.$previous;
			}
		return $ranges;
		}
	/*Get both add and sub ranges for a requested list*/
	function getFullRanges($listname)
		{
		$subranges = $this->getRanges($listname,'s');
		$addranges = $this->getRanges($listname,'a');
		return array("Subranges"=>$subranges,"Addranges"=>$addranges);		
		}
	/*Format a full request body for a desired list including
	  name and full ranges for add and sub*/
	function formattedRequest($listname)
		{
		$fullranges = $this->getFullRanges($listname);
		$buildpart = '';
		if(count($fullranges['Subranges'])>0)
			$buildpart .= 's:'.implode(',',$fullranges['Subranges']);
		if(count($fullranges['Subranges'])>0&&count($fullranges['Addranges'])>0)
			$buildpart .= ':';
		if(count($fullranges['Addranges'])>0)
			$buildpart .= 'a:'.implode(',',$fullranges['Addranges']);
		return $listname.';'.$buildpart."\n";
		}
	/*Called when GSB returns a SUB-DEL or ADD-DEL response*/
	function deleteRange($range,$mode,$listname)
		{
		$buildtrunk = $listname.'-'.$mode;
		if(substr_count($range,'-')>0)
			{
			$deleterange = explode('-',trim($range));
			$clause = "`ChunkNum` >= '{$deleterange[0]}' AND `ChunkNum` <= '{$deleterange[1]}'";
			}
		else
			$clause = "`ChunkNum` = '$range'";
		//Delete from index
		mysql_query("DELETE FROM `$buildtrunk-index` WHERE $clause");
		
		//Select all host keys that match chunks (we'll delete them after but we need the hostkeys list!)
		$result = mysql_query("SELECT `Hostkey` FROM `$buildtrunk-hosts` WHERE $clause");
		$buildprefixdel = array();
		if($result&&mysql_num_rows($result)>0)
			{
			while ($row = mysql_fetch_array($result, MYSQL_ASSOC))
				{
				if(!empty($row['Hostkey']))
					$buildprefixdel[] = $row['Hostkey'];
				}
			$mergeprefixdel = implode("' OR `Hostkey` = '",$buildprefixdel);
			//Delete all matching hostkey prefixes
			mysql_query("DELETE FROM `$buildtrunk-prefixes` WHERE `Hostkey` = '$mergeprefixdel'");
				
			//Delete all matching hostkeys
			mysql_query("DELETE FROM `$buildtrunk-hosts` WHERE $clause");	
			}
		}
	/*Main part of updater function, will call all other functions, merely requires 
	  the request body, it will then process and save all data as well as checking
	  for ADD-DEL and SUB-DEL, runs silently so won't return anything on success*/
	function getData($body)
		{
		if(empty($body))
			$this->fatalerror("Missing a body for data request");
		$this->trans_begin();
		$buildopts = array(CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$body."\n");
		$result = $this->googleDownloader("http://safebrowsing.clients.google.com/safebrowsing/downloads?client=api&apikey=".$this->apikey."&appver=".$this->version."&pver=".$this->apiversion,$buildopts,"data");
		preg_match('/^n:(.*)$/m', $result[1], $match);
		$timeout = $match[1];
		$this->setTimeout($timeout);
		if(substr_count($result[1],'r:pleasereset')>0)
			$this->resetDatabase();
		else
			{
			$formattedlist = array();
			if(substr_count($result[1],'i:')>0)
				{
				$splitlists = explode('i:',$result[1]);	
				unset($splitlists[0]);
				foreach($splitlists as $key=>$value)
					{
					$listdata = explode("\n",trim($value));
					$listname = $listdata[0];
					unset($listdata[0]);
					$formattedlist[$listname] = $listdata;				
					}
				foreach($formattedlist as $key=>$value)
					{	
					$listname = $key;
					foreach($value as $keyinner=>$valueinner)
						{
						if(substr_count($valueinner,"u:")>0)
							{
							$chunkdata = $this->googleDownloader('http://'.trim(str_replace('u:','',$valueinner)),false,"data");
							$processed = $this->processChunks($chunkdata[1],$listname);
							$this->outputmsg("Saved a chunk file");
							}
						elseif(substr_count($valueinner,"ad:")>0)
							{
							if(substr_count($valueinner,',')>0)
								{
								$valueinner = explode(',',trim(str_replace("ad:","",$valueinner)));
								foreach($valueinner as $keyadd=>$valueadd)
									{
									$this->deleteRange($valueadd,'a',$listname);									
									}
								}
							else
								$this->deleteRange(trim(str_replace("ad:","",$valueinner)),'a',$listname);
							}
						elseif(substr_count($valueinner,"sd:")>0)
							{
							if(substr_count($valueinner,',')>0)
								{
								$valueinner = explode(',',trim(str_replace("sd:","",$valueinner)));
								foreach($valueinner as $keyadd=>$valueadd)
									{
									$this->deleteRange($valueadd,'s',$listname);									
									}
								}
							else
								$this->deleteRange(trim(str_replace("sd:","",$valueinner)),'s',$listname);
							}
						}
						
					}
				}
			else
				{
				$this->outputmsg('No data available in list');	
				}
			}
		$this->trans_commit();
		return true;
		}
	/*Shortcut to run updater*/
	function runUpdate()
		{
		$this->checkTimeout('data');
		$require = "";
		foreach($this->usinglists as $value)
	    	$require .= $this->formattedRequest($value);	
		$this->outputmsg("Using $require");	
		$this->getData($require);
		}
	//LOOKUP FUNCTIONS
	/*Used to check the canonicalize function*/
	function validateMethod()
		{
		//Input => Expected
		$cases = array(
					   "http://host/%25%32%35" => "http://host/%25",
					   "http://host/%25%32%35%25%32%35" => "http://host/%25%25",
					   "http://host/%2525252525252525" => "http://host/%25",
					   "http://host/asdf%25%32%35asd" => "http://host/asdf%25asd",
					   "http://host/%%%25%32%35asd%%" => "http://host/%25%25%25asd%25%25",
					   "http://www.google.com/" => "http://www.google.com/",
					   "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/" => "http://168.188.99.26/.secure/www.ebay.com/",
					   "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/" => "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
					   "http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B" => 'http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+',
					   "http://3279880203/blah" => "http://195.127.0.11/blah",
					   "http://www.google.com/blah/.." => "http://www.google.com/",
					   "www.google.com/" => "http://www.google.com/",
					   "www.google.com" => "http://www.google.com/",
					   "http://www.evil.com/blah#frag" => "http://www.evil.com/blah",
					   "http://www.GOOgle.com/" => "http://www.google.com/",
					   "http://www.google.com.../" => "http://www.google.com/",
					   "http://www.google.com/foo\tbar\rbaz\n2" => "http://www.google.com/foobarbaz2",
					   "http://www.google.com/q?" => "http://www.google.com/q?",
					   "http://www.google.com/q?r?" => "http://www.google.com/q?r?",
					   "http://www.google.com/q?r?s" => "http://www.google.com/q?r?s",
					   "http://evil.com/foo#bar#baz" => "http://evil.com/foo",
					   "http://evil.com/foo;" => "http://evil.com/foo;",
					   "http://evil.com/foo?bar;" => "http://evil.com/foo?bar;",
					   "http://\x01\x80.com/" => "http://%01%80.com/",
					   "http://notrailingslash.com" => "http://notrailingslash.com/",
					   "http://www.gotaport.com:1234/" => "http://www.gotaport.com:1234/",
					   "  http://www.google.com/  " => "http://www.google.com/",
					   "http:// leadingspace.com/" => "http://%20leadingspace.com/",
					   "http://%20leadingspace.com/" => "http://%20leadingspace.com/",
					   "%20leadingspace.com/" => "http://%20leadingspace.com/",
					   "https://www.securesite.com/" => "https://www.securesite.com/",
					   "http://host.com/ab%23cd" => "http://host.com/ab%23cd",
					   "http://host.com//twoslashes?more//slashes" => "http://host.com/twoslashes?more//slashes"
					   );
		foreach($cases as $key=>$value)
			{
			$canit = $this->Canonicalize($key);
			$canit = $canit['GSBURL'];
			if($canit==$value)
				outputmsg("<span style='color:green'>PASSED: $key</span>");
			else
				outputmsg("<span style='color:red'>INVALID: <br>ORIGINAL: $key<br>EXPECTED: $value<br>RECIEVED: $canit<br> </span>");
				
			}
		}
	/*Special thanks Steven Levithan (stevenlevithan.com) for the ridiculously complicated regex
	  required to parse urls. This is used over parse_url as it robustly provides access to 
	  port, userinfo etc and handles mangled urls very well. 
	  Expertly integrated into phpGSB by Sam Cleaver ;)
	  Thanks to mikegillis677 for finding the seg. fault issue in the old function.
	  Passed validateMethod() check on 17/01/12*/
	function j_parseUrl($url) 
		{
		$strict = '/^(?:([^:\/?#]+):)?(?:\/\/\/?((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?))?(((?:\/(\w:))?((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/';
		$loose = '/^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/\/?)?((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?)(((?:\/(\w:))?(\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/';
		preg_match($loose, $url, $match);
		if(empty($match))
			{
			//As odd as its sounds, we'll fall back to strict (as technically its more correct and so may salvage completely mangled urls)
			unset($match);
			preg_match($strict, $url, $match);
			}
		$parts = array("source"=>'',"scheme"=>'',"authority"=>'',"userinfo"=>'',"user"=>'',"password"=>'',"host"=>'',"port"=>'',"relative"=>'',"path"=>'',"drive"=>'',"directory"=>'',"file"=>'',"query"=>'',"fragment"=>'');
		  switch (count ($match)) {  
			case 15: $parts['fragment'] = $match[14];
			case 14: $parts['query'] = $match[13];
			case 13: $parts['file'] =  $match[12];
			case 12: $parts['directory'] =  $match[11];
			case 11: $parts['drive'] =  $match[10];
			case 10: $parts['path'] =  $match[9];
			case 9: $parts['relative'] =  $match[8];
			case 8: $parts['port'] =  $match[7];
			case 7: $parts['host'] =  $match[6];
			case 6: $parts['password'] =  $match[5];
			case 5: $parts['user'] =  $match[4];
			case 4: $parts['userinfo'] =  $match[3];
			case 3: $parts['authority'] =  $match[2];
			case 2: $parts['scheme'] =  $match[1];
			case 1: $parts['source'] =  $match[0];
		  }
		return $parts;
		}
	/*Regex to check if its a numerical IP address*/
	function is_ip($ip) 
		{
		return preg_match("/^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])" .
				"(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$/", $ip);
		} 
	/*Checks if input is in hex format*/
	function is_hex($x) 
		{
		//Relys on the fact that hex often includes letters meaning PHP will disregard the string
		if(($x+3) == 3)
			return dechex(hexdec($x)) == $x;
		return false;
		}
	/*Checks if input is in octal format*/
	function is_octal($x)
		{
		//Relys on the fact that in IP addressing octals must begin with a 0 to denote octal
		return substr($x,0,1) == 0;
		}
	/*Converts hex or octal input into decimal */
	function hexoct2dec($value)
		{
		//As this deals with parts in IP's we can be more exclusive
		if(substr_count(substr($value,0,2),'0x')>0&&$this->is_hex($value))
				{
				return hexdec($value);
				}
			elseif($this->is_octal($value))
				{
				return octdec($value);	
				}
			else
				return false;
		}
	/*Converts IP address part in HEX to decimal*/
	function iphexdec($hex)
		{
		//Removes any leading 0x (used to denote hex) and then and leading 0's)
		$temp = str_replace('0x','',$hex);
		$temp = ltrim($temp,"0");	
		return hexdec($temp);
		}
	/*Converts full IP address in HEX to decimal*/
	function hexIPtoIP($hex)
		{
		//Remove hex identifier and leading 0's (not significant)
		$tempip = str_replace('0x','',$hex);
		$tempip = ltrim($tempip,"0");	
		//It might be hex
		if($this->is_hex($tempip))
			{
			//There may be a load of junk before the part we need
			if(strlen($tempip)>8)
				{
				$tempip = substr($tempip,-8);	
				}
			$hexplode = preg_split('//', $tempip, -1, PREG_SPLIT_NO_EMPTY);
			while(count($hexplode)<8)
				array_unshift($hexplode,0);
			//Normalise
			$newip = hexdec($hexplode[0].$hexplode[1]).'.'.hexdec($hexplode[2].$hexplode[3]).'.'.hexdec($hexplode[4].$hexplode[5]).'.'.hexdec($hexplode[6].$hexplode[7]);
			//Now check if its an IP
			if($this->is_ip($newip))
				return $newip;
			else
				return false;
			}
		else
			return false;
		}
	/*Checks if an IP provided in either hex, octal or decimal is in fact
	  an IP address. Normalises to a four part IP address.*/
	function isValid_IP($ip)
		{
		//First do a simple check, if it passes this no more needs to be done	
		if($this->is_ip($ip))
			return $ip;
		
		//Its a toughy... eerm perhaps its all in hex?
		$checkhex = $this->hexIPtoIP($ip);
		if($checkhex)
			return $checkhex;
		
		//If we're still here it wasn't hex... maybe a DWORD format?
		$checkdword = $this->hexIPtoIP(dechex($ip));
		if($checkdword)
			return $checkdword;
		
		//Nope... maybe in octal or a combination of standard, octal and hex?!
		$ipcomponents = explode('.',$ip);
		$ipcomponents[0] = $this->hexoct2dec($ipcomponents[0]);
		if(count($ipcomponents)==2)
			{
			//The writers of the RFC docs certainly didn't think about the clients! This could be a DWORD mixed with an IP part
			if($ipcomponents[0]<=255&&is_int($ipcomponents[0])&&is_int($ipcomponents[1]))
				{
				$threeparts = dechex($ipcomponents[1]);
				$hexplode = preg_split('//', $threeparts, -1, PREG_SPLIT_NO_EMPTY);
				if(count($hexplode)>4)
					{
					$newip = $ipcomponents[0].'.'.$this->iphexdec($hexplode[0].$hexplode[1]).'.'.$this->iphexdec($hexplode[2].$hexplode[3]).'.'.$this->iphexdec($hexplode[4].$hexplode[5]);
					//Now check if its valid
					if($this->is_ip($newip))
						return $newip;
					}
				}	
			}
		$ipcomponents[1] = $this->hexoct2dec($ipcomponents[1]);
		if(count($ipcomponents)==3)
			{
			//Guess what... it could also be a DWORD mixed with two IP parts!
			if(($ipcomponents[0]<=255&&is_int($ipcomponents[0]))&&($ipcomponents[1]<=255&&is_int($ipcomponents[1]))&&is_int($ipcomponents[2]))
				{
				$twoparts = dechex($ipcomponents[2]);
				$hexplode = preg_split('//', $twoparts, -1, PREG_SPLIT_NO_EMPTY);
				if(count($hexplode)>3)
					{
					$newip = $ipcomponents[0].'.'.$ipcomponents[1].'.'.$this->iphexdec($hexplode[0].$hexplode[1]).'.'.$this->iphexdec($hexplode[2].$hexplode[3]);
					//Now check if its valid
					if($this->is_ip($newip))
						return $newip;
					}
				}	
			}
		//If not it may be a combination of hex and octal
		if(count($ipcomponents)>=4)
		  {
		  $tmpcomponents = array($ipcomponents[2],$ipcomponents[3]);
		  foreach($tmpcomponents as $key=>$value)
			  {
			  if(!$tmpcomponents[$key] = $this->hexoct2dec($value))
				  return false;	
			  }
		  
		  array_unshift($tmpcomponents,$ipcomponents[0],$ipcomponents[1]);
		  //Convert back to IP form
		  $newip = implode('.',$tmpcomponents);
		  
		  //Now check if its valid
		  if($this->is_ip($newip))
			  return $newip;
		  }
	
		//Well its not an IP that we can recognise... theres only so much we can do!
		return false;
		}
	/*Had to write another layer as built in PHP urlencode() escapes all non
	  alpha-numeric Google states to only urlencode if its below 32 or above
	  or equal to 127 (some of those are non alpha-numeric and so urlencode
	  on its own won't work).*/
	function flexURLEncode($url,$ignorehash=false)
		{
		//Had to write another layer as built in PHP urlencode() escapes all non alpha-numeric
		//google states to only urlencode if its below 32 or above or equal to 127 (some of those
		//are non alpha-numeric and so urlencode on its own won't work).
		$urlchars = preg_split('//', $url, -1, PREG_SPLIT_NO_EMPTY);
		if(count($urlchars)>0)
			{
			foreach($urlchars as $key=>$value)
				{
				
				$ascii = ord($value);
				if($ascii<=32||$ascii>=127||($value=='#'&&!$ignorehash)||$value=='%')
					$urlchars[$key] = rawurlencode($value);
				}
			return implode('',$urlchars);
			}
		else
			return $url;
		}
	/*Canonicalize a full URL according to Google's definition.*/
	function Canonicalize($url)
		{
		//Remove line feeds, return carriages, tabs, vertical tabs
		$finalurl = trim(str_replace(array("\x09","\x0A","\x0D","\x0B"),'',$url));
		//URL Encode for easy extraction
		$finalurl = $this->flexURLEncode($finalurl,true);
		//Now extract hostname & path
		$parts = $this->j_parseUrl($finalurl);
		$hostname = $parts['host'];
		$path = $parts['path'];
		$query = $parts['query'];
		$lasthost = "";
		$lastpath = "";
		$lastquery = "";
		//Remove all hex coding (loops max of 50 times to stop craziness but should never
		//reach that)
		for ($i = 0; $i < 50; $i++) {
		$hostname = rawurldecode($hostname);
		$path = rawurldecode($path);
		$query = rawurldecode($query);
		if($hostname==$lasthost&&$path==$lastpath&&$query==$lastquery)
			break;
		$lasthost = $hostname;
		$lastpath = $path;
		$lastquery = $query;
		}
		//Deal with hostname first
		//Replace all leading and trailing dots
		$hostname = trim($hostname,'.');
		//Replace all consecutive dots with one dot
		$hostname = preg_replace("/\.{2,}/",".",$hostname);
		//Make it lowercase
		$hostname = strtolower($hostname);
		//See if its a valid IP
		$hostnameip = $this->isValid_IP($hostname);
		if($hostnameip)
			{
			$usingip = true;
			$usehost = $hostnameip;
			}
		else
			{
			$usingip = false;
			$usehost = $hostname;
			}
		//The developer guide has lowercasing and validating IP other way round but its more efficient to
		//have it this way
		//Now we move onto canonicalizing the path
		$pathparts = explode('/',$path);
		foreach($pathparts as $key=>$value)
			{
			if($value=="..")
				{
				if($key!=0)
					{
					unset($pathparts[$key-1]);
					unset($pathparts[$key]);
					}
				else
					unset($pathparts[$key]);
				}
			elseif($value=="."||empty($value))
				unset($pathparts[$key]);
			}
		if(substr($path,-1,1)=="/")
			$append = "/";
		else
			$append = false;
		$path = "/".implode("/",$pathparts);
		if($append&&substr($path,-1,1)!="/")
			$path .= $append;
		$usehost = $this->flexURLEncode($usehost);
		$path = $this->flexURLEncode($path);
		$query = $this->flexURLEncode($query);
		if(empty($parts['scheme']))
			$parts['scheme'] = 'http';
		$canurl = $parts['scheme'].'://';
		$realurl = $canurl;
		if(!empty($parts['userinfo']))
			$realurl .= $parts['userinfo'].'@';
		$canurl .= $usehost;
		$realurl .= $usehost;
		if(!empty($parts['port']))
			{
			$canurl .= ':'.$parts['port'];
			$realurl .= ':'.$parts['port'];
			}
		$canurl .= $path;
		$realurl .= $path;
		if(substr_count($finalurl,"?")>0)
			{
			$canurl .= '?'.$parts['query'];
			$realurl .= '?'.$parts['query'];
			}
		if(!empty($parts['fragment']))
			$realurl .= '#'.$parts['fragment'];
		return array("GSBURL"=>$canurl,"CleanURL"=>$realurl,"Parts"=>array("Host"=>$usehost,"Path"=>$path,"Query"=>$query,"IP"=>$usingip));
		}
	/*SHA-256 input (short method).*/
	function sha256($data)
		{
		return hash('sha256',$data);	
		}
	/*Make Hostkeys for use in a lookup*/
	function makeHostKey($host,$usingip)

		{
		if($usingip)
			$hosts = array($host."/");

		else
			{
			$hostparts = explode(".",$host);
			if(count($hostparts)>2)
				{
				$backhostparts = array_reverse($hostparts);
				$threeparts = array_slice($backhostparts,0,3);
				$twoparts = array_slice($threeparts,0,2);
				$hosts = array(implode('.',array_reverse($threeparts))."/",implode('.',array_reverse($twoparts))."/");
				}
			else
				$hosts = array($host."/");
			}
		//Now make key & key prefix
		$returnhosts = array();
		foreach($hosts as $value)
			{
			$fullhash = $this->sha256($value);
			$returnhosts[$fullhash] = array("Host"=>$value,"Prefix"=>substr($fullhash,0,8),"Hash"=>$fullhash);	
			}
		return $returnhosts;
		}
	/*Hash up a list of values from makePrefixes() (will possibly be
	  combined into that function at a later date*/
	function makeHashes($prefixarray)
		{
		if(count($prefixarray)>0)
			{
			$returnprefixes = array();
			foreach($prefixarray as $value)
				{
				$fullhash = $this->sha256($value);
				$returnprefixes[$fullhash] = array("Original"=>$value,"Prefix"=>substr($fullhash,0,8),"Hash"=>$fullhash);	
				}
			return $returnprefixes;
			}
		else
			return false;
		}
	/*Make URL prefixes for use after a hostkey check*/
	function makePrefixes($host,$path,$query,$usingip)
		{
		$prefixes = array();	
		//Exact hostname in the url	
		$hostcombos = array();
		$hostcombos[] = $host;
		if(!$usingip)
			{
			$hostparts = explode('.',$host);
			$backhostparts = array_reverse($hostparts);
			if(count($backhostparts)>5)
				$maxslice = 5;
			else
				$maxslice = count($backhostparts);
			$topslice = array_slice($backhostparts,0,$maxslice);
			while($maxslice>1)
				{
				$hostcombos[] = implode('.',array_reverse($topslice));
				$maxslice--;
				$topslice = array_slice($backhostparts,0,$maxslice);
				}
			}
		else
			$hostcombos[] = $host;
		$hostcombos = array_unique($hostcombos);
		$variations = array();
		if(!empty($path))
				{
				$pathparts = explode("/",$path);
				if(count($pathparts)>4)
							$upperlimit = 4;
						else
							$upperlimit = count($pathparts);
				}
		foreach($hostcombos as $key=>$value)
			{
			if(!empty($query))
				$variations[] = $value.$path.'?'.$query;
			$variations[] = $value.$path;
			if(!empty($path))
				{
				$i = 0;
				$pathiparts = "";
				while($i<$upperlimit)
					{
					if($i!=count($pathparts)-1)
						$pathiparts = $pathiparts.$pathparts[$i]."/";
					else
						$pathiparts = $pathiparts.$pathparts[$i];
					$variations[] = $value.$pathiparts;
					$i++;
					}
				}
			}
		$variations = array_unique($variations);
		return $this->makeHashes($variations);	
		}
	/*Process data provided from the response of a full-hash GSB
	  request*/
	function processFullLookup($data)
		{
		$clonedata = $data;
		$extracthash = array();
		while(strlen($clonedata)>0)
			{
			$splithead = explode("\n",$clonedata,2);
			$chunkinfo = explode(':',$splithead[0]);
			$listname = $chunkinfo[0];
			$addchunk = $chunkinfo[1];
			$chunklen = $chunkinfo[2];
			$chunkdata = bin2hex(substr($splithead[1],0,$chunklen));
			while(strlen($chunkdata)>0)
						{
						$extracthash[$listname][$addchunk] = substr($chunkdata,0,64);
						$chunkdata = substr($chunkdata,64);	
						}
			$clonedata = substr($splithead[1],$chunklen);
			}
		return $extracthash;
		}
	/*Add a full-hash key to a prefix or hostkey (the variable is $prefix but it could
	  be either).*/
	function addFullHash($prefix,$chunknum,$fullhash,$listname)
		{
		$buildtrunk = $listname."-a";
		//First check hosts
		$result = mysql_query("SELECT * FROM `$buildtrunk-hosts` WHERE `Hostkey` = '$prefix' AND `Chunknum` = '$chunknum'");
		if($result&&mysql_num_rows($result)>0)
			{
			while ($row = mysql_fetch_array($result, MYSQL_ASSOC))
						  {
						  if(empty($row['FullHash']))
							  {
							  //We've got a live one! Insert the full hash for it	
							  $addresult = mysql_query("UPDATE `$buildtrunk-hosts` SET `FullHash` = '$fullhash' WHERE `ID` = '{$row['ID']}';");
							  if(!$addresult)
							  		$this->fatalerror("Could not cache full-hash key. $prefix, $chunknum, $fullhash, $listname");
							  }
						  }
			}
		else
			{
			//If there are no rows it must be a prefix	
			$result = mysql_query("SELECT * FROM `$buildtrunk-prefixes` WHERE `Prefix` = '$prefix'");
			while ($row = mysql_fetch_array($result, MYSQL_ASSOC))
						  {
						  if(empty($row['FullHash']))
							  {
							  $resulttwo = mysql_query("SELECT * FROM `$buildtrunk-hosts` WHERE `Hostkey` = '{$row['Hostkey']}' AND `Chunknum` = '$chunknum'");
							  while ($rowtwo = mysql_fetch_array($resulttwo, MYSQL_ASSOC))
								  {
								  if(hexdec($rowtwo['Count'])>0)
									  {
									  $addresult = mysql_query("UPDATE `$buildtrunk-prefixes` SET `FullHash` = '$fullhash' WHERE `ID` = '{$row['ID']}';");	
									  if(!$addresult)
										  $this->fatalerror("Could not cache full-hash key. $prefix, $chunknum, $fullhash, $listname");
									  }
								  }
							  }
						  }
			}
			
		}
	/*Check database for any cached full-length hashes for a given prefix.*/
	function cacheCheck($prefix)
		{
		foreach($this->usinglists as $value)
			{
			$buildtrunk = $value."-a";
			$result = mysql_query("SELECT * FROM `$buildtrunk-hosts` WHERE `Hostkey` = '$prefix' AND `FullHash` != ''");
			if($result&&mysql_num_rows($result)>0)
				{
				while($row = mysql_fetch_array($result, MYSQL_ASSOC))
					{
					return array($row['FullHash'],$row['Chunknum']);				
					}	
				}
			else
				{
				$result = mysql_query("SELECT * FROM `$buildtrunk-prefixes` WHERE `Prefix` = '$prefix' AND `FullHash` != ''");
				if($result&&mysql_num_rows($result)>0)
					{
					while($row = mysql_fetch_array($result, MYSQL_ASSOC))
						{	
						$resulttwo = mysql_query("SELECT * FROM `$buildtrunk-hosts` WHERE `Hostkey` = '{$row['Hostkey']}'");
						while ($rowtwo = mysql_fetch_array($resulttwo, MYSQL_ASSOC))
									  {
										if(hexdec($rowtwo['Count'])>0)
										  {
										   return array($row['FullHash'],$rowtwo['Chunknum']);	
										  }
										  
									  }		
						}
					}					
				}
			}
		return false;
		}
	/*Do a full-hash lookup based on prefixes provided, returns (bool) true
	  on a match and (bool) false on no match.*/
	function doFullLookup($prefixes,$originals)
		{
		//Store copy of original prefixes
		$cloneprefixes = $prefixes;
		//They should really all have the same prefix size.. we'll just check one
		$prefixsize = strlen($prefixes[0][0])/2;
		$length = count($prefixes)*$prefixsize;
		foreach($prefixes as $key=>$value)
			{
			//Check cache on each iteration (we can return true earlier if we get a match!)
			$cachechk = $this->cacheCheck($value[0]);
			if($cachechk)
				{
				if(isset($originals[$cachechk[0]]))
					{
					//Check from same chunk	
					foreach($cloneprefixes as $nnewvalue)
							{
							if($nnewvalue[1]==$cachechk[1]&&$value[0]==$originals[$cachechk[0]]['Prefix'])
								{
								//From same chunks
								return true;
								}
								
							}
					}
				}
			$prefixes[$key] = pack("H*",$value[0]);
			}
		//No cache matches so we continue with request
		$body = "$prefixsize:$length\n".implode("",$prefixes);

		$buildopts = array(CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$body);
		$result = $this->googleDownloader("http://safebrowsing.clients.google.com/safebrowsing/gethash?client=api&apikey=".$this->apikey."&appver=".$this->version."&pver=".$this->apiversion,$buildopts,"lookup");
	
		if($result[0]['http_code']==200&&!empty($result[1]))
			{
			//Extract hashes from response
			$extractedhashes = $this->processFullLookup($result[1]);
			//Loop over each list
			foreach($extractedhashes as $key=>$value)
				{
				//Loop over each value in each list
				foreach($value as $newkey=>$newvalue)
					{
					if(isset($originals[$newvalue]))
						{
						//Okay it matches a full-hash we have, now to check they're from the same chunks
						foreach($cloneprefixes as $nnewvalue)
							{
							if($nnewvalue[1]==$newkey&&$nnewvalue[0]==$originals[$newvalue]['Prefix'])
								{
								//From same chunks
								//Add full hash to database (cache)
								$this->addFullHash($nnewvalue[0],$nnewvalue[1],$newvalue,$key);
								return true;
								}
								
							}
						}
					}
				}
			return false;		
			}
		elseif($result[0]['http_code']==204&&strlen($result[1])==0)
			{
			//204 Means no match
			return false;	
			}
		else
			{
			//"No No No! This just doesn't add up at all!"	
			$this->fatalerror("ERROR: Invalid response returned from GSB ({$result[0]['http_code']})");
			}
		}
	/*Checks to see if a match for a prefix is found in the sub table, if it is then we won't do
	  a full-hash lookup. Return true on match in sub list, return false on negative.*/
	function subCheck($listname,$prefixlist,$mode)
		{
		$buildtrunk = $listname.'-s';
		if($mode=="prefix")
			{
			//Mode is prefix so the add part was a prefix, not a hostkey so we just check prefixes (saves a lookup)
			foreach($prefixlist as $value)
				{
				$result = mysql_query("SELECT * FROM `$buildtrunk-prefixes` WHERE `Prefix` = '{$value[0]}'");
				if($result&&mysql_num_rows($result)>0)
				  {
				  //As interpreted from Developer Guide if theres a match in sub list it cancels out the add listing
				  //we'll double check its from the same chunk just to be pedantic
				  while ($row = mysql_fetch_array($result, MYSQL_ASSOC))
					  {
					  if(hexdec($row['AddChunkNum'])==$value[1])
					  	return true;
					  }
				  }
				
				}
			return false;
			}
		elseif($mode=="hostkey")
			{
			//Mode is hostkey
			foreach($prefixlist as $value)
				{
				$result = mysql_query("SELECT * FROM `$buildtrunk-prefixes` WHERE `Hostkey` = '{$value[0]}'");
				if($result&&mysql_num_rows($result)>0)
				  {
				  //As interpreted from Developer Guide if theres a match in sub list it cancels out the add listing
				  //we'll double check its from the same chunk just to be pedantic
				  while ($row = mysql_fetch_array($result, MYSQL_ASSOC))
					  {
					  if(hexdec($row['AddChunkNum'])==$value[1]&&empty($row['Prefix']))
					  	return true;
					  }
				  }
				
				}
			return false;
			}
		$this->fatalerror("Invalid SubCheck Mode $mode");
		}
	/*Does a full URL lookup on given lists, will check if its in database, if slight match there then 
	  will do a full-hash lookup on GSB, returns (bool) true on match and (bool) false on negative.*/
	function doLookup($url)
		{
		$lists = $this->usinglists;
		//First canonicalize the URL
		$canurl = $this->Canonicalize($url);
		//Make hostkeys
		$hostkeys = $this->makeHostKey($canurl['Parts']['Host'],$canurl['Parts']['IP']);
		$matches = array();
		foreach($lists as $key=>$value)
			{
			$buildtrunk = $value.'-a';
			//Loop over each list
			foreach($hostkeys as $keyinner=>$valueinner)
				{
				//Within each list loop over each hostkey	
				$result = mysql_query("SELECT * FROM `$buildtrunk-hosts` WHERE `Hostkey` = '{$valueinner['Prefix']}'");
				if($result&&mysql_num_rows($result)>0)
				  {
				  //For each hostkey match
				  while ($row = mysql_fetch_array($result, MYSQL_ASSOC))
					  {
					  $nicecount = hexdec($row['Count']);
					  if($nicecount>0)
						{
						//There was a match and the count is more than one so there are prefixes!
						//Hash up a load of prefixes and create the build query if we haven't done so already
						if(!isset($prefixes))
							{
							$prefixes = $this->makePrefixes($canurl['Parts']['Host'],$canurl['Parts']['Path'],$canurl['Parts']['Query'],$canurl['Parts']['IP']);
							$buildprequery = array();
							foreach($prefixes as $key=>$value)
								{
								$buildprequery[] = " `Prefix` = '{$value['Prefix']}' ";	
								}
							$buildprequery = implode("OR",$buildprequery);
							}
						//Check if there are any matching prefixes
						$resulttwo = mysql_query("SELECT * FROM `$buildtrunk-prefixes` WHERE ($buildprequery) AND `Hostkey` = '{$row['Hostkey']}'");
						if($resulttwo&&mysql_num_rows($resulttwo)>0)
							{
							//We found prefix matches	
							$prematches = array();
							$prelookup = array();
							while ($rowtwo = mysql_fetch_array($resulttwo, MYSQL_ASSOC))
								{
								$prematches[] = array($rowtwo['Prefix'],$row['Chunknum']);
								}
							//Before we send off any requests first check whether its in sub table
							$subchk = $this->subCheck($value,$prematches,"prefix");
							if(!$subchk)
								{
								//Send off any matching prefixes to do some full-hash key checks
								$flookup = $this->doFullLookup($prematches,$prefixes);
								if($flookup)
									return true;
								}
							}
						//If we didn't find matches then do nothing (keep looping till end and it'll return negative)	
						}
					else
						{
						$subchk = $this->subCheck($value,array(array($row['Hostkey'],$row['Chunknum'])),"hostkey");
						if(!$subchk)
							{
							//There was a match but the count was 0 that entire domain could be a match, Send off to check
							$flookup = $this->doFullLookup(array(array($row['Hostkey'],$row['Chunknum'])),$hostkeys);
							if($flookup)
								return true;
							}
						}
					  }
				  }	
				}
			}
		return false;	
			
		}	
	}
?>