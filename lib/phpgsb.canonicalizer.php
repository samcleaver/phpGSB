<?php
/**
 * phpGSB - PHP Google Safe Browsing Implementation
 * --> URL Canonicalization Functions
 * A standalone canonicalizer that follows GSB
 * specifications.
 * 
 * Requires: PHP version 5+
 * 
 * @category Anti-Spam
 * @package  PHPGSB
 * @author   Sam Cleaver <cleaver.sam@gmail.com>
 * @license  New BSD License (see LICENSE)
 * @link     https://github.com/Beaver6813/phpGSB
 */

class phpGSB_Canonicalizer {
    
    public function __construct($url) {
        $this->process($url);
    }
    
    public function process($url) {
        //Trim unwanted whitespace
        $outputurl = trim(str_replace(array("\x09","\x0A","\x0D","\x0B"),'',$url));
        //Encode the URL
        $outputurl = $this->urlencode($outputurl, true);
        //Extract URL information
        $urlparts = $this->parseURL($outputurl);
        var_dump($urlparts);
    }
    
    private function urlencode($url, $ignorehash = false) {
        $urlchars = preg_split('//', $url, -1, PREG_SPLIT_NO_EMPTY);
        if(count($urlchars)>0) {
            foreach($urlchars as $key=>$value) {
                $ascii = ord($value);
                if($ascii<=32||$ascii>=127||($value=='#'&&!$ignorehash)||$value=='%')
                    $urlchars[$key] = rawurlencode($value);
            }
            return implode('',$urlchars);
        } else
            return $url;
    }
    
    /*
     * Special thanks Steven Levithan (stevenlevithan.com) for the ridiculously complicated regex
     * required to parse urls. This is used over parse_url as it robustly provides access to 
     * port, userinfo etc and handles mangled urls very well. 
     */
    private function parseURL($url) {
        $match = '';
        $strict = '/^(?:([^:\/?#]+):)?(?:\/\/\/?((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?))?(((?:\/(\w:))?((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/';
        $loose = '/^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/\/?)?((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?)(((?:\/(\w:))?(\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/';
        preg_match($loose, $url, $match);
        if(empty($match)) {
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
    
    
    
}