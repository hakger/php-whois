<?php

namespace Phois\Whois;

class Whois
{
    private $domain;

    private $TLDs;

    private $subDomain;

    private $servers;
    private $whoisserver;
    private $whoisInfo; 
    var $socTimeout = 5;
    var $socErrno;
    var $socErrstr;

    /**
     * @param string $domain full domain name (without trailing dot)
     */
    public function __construct($domain, $proxy = false)
    {
        $this->domain = $domain;
        // check $domain syntax and split full domain name on subdomain and TLDs
        if (
            preg_match('/^([\p{L}\d\-]+)\.((?:[\p{L}\-]+\.?)+)$/ui', $this->domain, $matches)
            || preg_match('/^(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[a-z\d-]+\.?1?)+)$/ui', $this->domain, $matches)
        ) {
            $this->subDomain = $matches[1];
            $this->TLDs = $matches[2];
            if ($proxy) {
                $this->proxy = $proxy;
            }
        } else
            throw new \InvalidArgumentException("Invalid $domain syntax");
        // setup whois servers array from json file
        $this->servers = json_decode(file_get_contents( __DIR__.'/whois.servers.json' ), true);
        if (!$this->isValid())
        	throw new \InvalidArgumentException("Domain name isn't valid!");
    }

    public function setWhoisServer($hostname, $availiable)
    {
        $this->whoisserver = array($hostname, $avaiable);
    }
    
    public function getWhoisServer() 
    {
        if ( $this->whoisserver ) {
            return $this->whoisserver;
        }
        return $this->servers[$this->TLDs];
    }


    /**
     * @param string, domain whois information
     */
    public function info()
    {
        if ($this->whoisInfo != '')
            return $this->whoisInfo;
        if ($this->isValid()) {
            $whois_server = $this->getWhoisServer();

            // If TLDs have been found
            if ($whois_server != '') {

                // if whois server serve reply over HTTP protocol instead of WHOIS protocol
                if (preg_match("/^https?:\/\//i", $whois_server)) {

                    // curl session to get whois reposnse
                    $ch = curl_init();
                    $url = $whois_server . $this->subDomain . '.' . $this->TLDs;
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                    if ($proxy) {
                        curl_setopt($ch, CURLOPT_PROXY, $proxy['ip']);
                        curl_setopt($ch, CURLOPT_PROXYPORT, $proxy['port']);
                    }

                    $data = curl_exec($ch);

                    if (curl_error($ch)) {
                        return "Connection error!";
                    } else {
                        $string = strip_tags($data);
                    }
                    curl_close($ch);

                } else {

                    // Getting whois information
                    $fp = fsockopen($whois_server, 43, $this->socErrno, $this->socErrstr, $this->socTimeout);
                    if (!$fp) {
                        return "Connection error! ".$this->socErrno.":".$this->socErrstr;
                    }
                    stream_set_blocking($fp, TRUE); 
                    stream_set_timeout($fp,$this->socTimeout); 
                    $info = stream_get_meta_data($fp); 

                    $dom = $this->subDomain . '.' . $this->TLDs;
                    fputs($fp, "$dom\r\n");

                    // Getting string
                    $string = '';

                    // Checking whois server for .com and .net
                    if ($this->TLDs == 'com' || $this->TLDs == 'net') {
                        while ( (!feof($fp)) && (!$info['timed_out']) ) {
                            $line = trim(fgets($fp, 128));

                            $string .= $line;

                            $lineArr = explode (":", $line);

                            if (strtolower($lineArr[0]) == 'whois server') {
                                $whois_server = trim($lineArr[1]);
                            }
                            $info = stream_get_meta_data($fp); 
                        }
                        // Getting whois information
                        $fp = fsockopen($whois_server, 43, $this->socErrno, $this->socErrstr, $this->socTimeout);
                        if (!$fp) {
                            return "Connection error! ".$this->socErrno.":".$this->socErrstr;;
                        }
                        stream_set_blocking($fp, TRUE); 
                        stream_set_timeout($fp,$this->socTimeout); 
                        $info = stream_get_meta_data($fp); 

                        $dom = $this->subDomain . '.' . $this->TLDs;
                        fputs($fp, "$dom\r\n");

                        // Getting string
                        $string = '';

                        while (!feof($fp)) {
                            $string .= fgets($fp, 128);
                        }

                        // Checking for other tld's
                    } else {
                       while ( (!feof($fp)) && (!$info['timed_out']) ) {
                            $string .= fgets($fp, 128);
                            $info = stream_get_meta_data($fp); 
                        }
                    }
                    fclose($fp);
                }

                $string_encoding = mb_detect_encoding($string, "UTF-8, ISO-8859-1, ISO-8859-15", true);
                $string_utf8 = mb_convert_encoding($string, "UTF-8", $string_encoding);

                $this->whoisInfo = htmlspecialchars($string_utf8, ENT_COMPAT, "UTF-8", true);
                return $this->whoisInfo;
            } else {
                return "No whois server for this tld in list!";
            }
        } else {
            return "Domain name isn't valid!";
        }
    }

    public function htmlInfo()
    {
        return nl2br($this->info());
    }

    /**
     * @return string full domain name
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * @return string top level domains separated by dot
     */
    public function getTLDs()
    {
        return $this->TLDs;
    }

    /**
     * @return string return subdomain (low level domain)
     */
    public function getSubDomain()
    {
        return $this->subDomain;
    }

	/**
     * @return boolean, true for domain avaliable, false for domain registered
     */
    public function isAvailable()
    {
        if ($this->whoisInfo == '')
        $whois_string = $this->info();
        else 
        	$whois_string = $this->whoisInfo;
        $not_found_string = '';
        if (isset($this->servers[$this->TLDs][1])) {
           $not_found_string = $this->servers[$this->TLDs][1];
        }

        $whois_string2 = @preg_replace('/' . $this->domain . '/', '', $whois_string);
        $whois_string = @preg_replace("/\s+/", ' ', $whois_string);

		$return = true;

		if (is_array($not_found_strings)) {
			foreach ($not_found_strings as $not_found_string) {
        $array = explode (":", $not_found_string);
        if ($array[0] == "MAXCHARS") {
            if (strlen($whois_string2) <= $array[1]) {
						$return = true;
            } else {
						$return = false;
					}
				} else if ($array[0] == "NEGATION") {
					if (preg_match("/" . $array[1] . "/i", $whois_string)) {
						$return = false;
					} else {
						$return = true;
            }
        } else {
            if (preg_match("/" . $not_found_string . "/i", $whois_string)) {
						$return &= true;
            } else {
						$return &= false;
            }
        }
			}
		}
		return $return;
    }

    public function isValid()
    {
        if (
            isset($this->servers[$this->TLDs][0])
            && strlen($this->servers[$this->TLDs][0]) > 6
        ) {
            $tmp_domain = strtolower($this->subDomain);
            if (
                preg_match("/^[=]?[a-z0-9\-]+$/", $tmp_domain)
                && !preg_match("/^-|-$/", $tmp_domain) //&& !preg_match("/--/", $tmp_domain)
            ) {
                return true;
            }
        }

        return false;
    }
    
    public function getServers() {
        return $this->servers;
    }
}
