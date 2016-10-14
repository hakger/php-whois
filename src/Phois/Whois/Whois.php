<?php

namespace Phois\Whois;

/**
 *
 */
class Whois
{
    /**
     * Full domain name, as passed to constructor
     * @var string
     */
    private $domain;

    /**
     * Domain TLD, extracted from domain
     * @var string
     */
    private $TLDs;

    /**
     * Domain SLD, extracted from domain
     * @var string
     */
    private $subDomain;

    /**
     * Servers and Availability patterns for TLDs
     * @var array
     */
    private $servers;

    /**
     * Custom whois server (if set)
     * @var null|array
     */
    private $whoisserver = null;

    /**
     * Whois info cache - reduces amount of calls to external servers
     * @var string
     */
    private $whoisInfo;

    /**
     * Proxy for cURL connections
     * @var null|array
     */
    private $proxy = null;

    /**
     * SocketTimeout
     * @var int
     */
    private $socTimeout = 5;

    /**
     * Socket error code
     * @var int
     */
    private $socErrno;

    /**
     * Socket error description
     * @var string
     */
    private $socErrstr;

    /**
     * @param string $domain full domain name (without trailing dot)
     * @param array  $proxy  array containing 'ip' and 'port' keys for curl proxy
     */
    public function __construct($domain, $proxy = null)
    {
        $this->domain = mb_strtolower($domain);
        // check $domain syntax and split full domain name on subdomain and TLDs
        $matches = array();
        if (!preg_match(
            '/^[=]?([\p{L}\d\-]+)\.((?:[\p{L}\-]+\.?)+)$/ui',
            $this->domain,
            $matches
        ) && !preg_match(
            '/^[=]?(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[a-z\d-]+\.?1?)+)$/ui',
            $this->domain,
            $matches
        )) {
            throw new \InvalidArgumentException("Invalid $domain syntax");
        }
        $this->subDomain = $matches[1];
        $this->TLDs = $matches[2];
        if ($proxy) {
            $this->proxy = $proxy;
        }
        // setup whois servers array from json file
        $this->servers = json_decode(
            file_get_contents(__DIR__.'/whois.servers.json'),
            true
        );
        if (!$this->isValid()) {
            throw new \InvalidArgumentException("Domain name isn't valid!");
        }
    }

    /**
     * Set custom whois server for all calls.
     *
     * @param string $hostname   WHOIS server hostname
     * @param string $available Pattern to check domain availability
     */
    public function setWhoisServer($hostname, $available)
    {
        $this->whoisserver = array($hostname, $available);
    }

    /**
     * Get WHOIS server to use with call.
     *
     * @return array Server and availability pattern
     */
    public function getWhoisServer()
    {
        if ($this->whoisserver) {
            return $this->whoisserver;
        }

        return $this->servers[$this->TLDs];
    }

    /**
     * Get WHOIS info.
     *
     * @return string Whois info as returned by WHOIS server
     */
    public function info()
    {
        if ($this->whoisInfo != '') {
            return $this->whoisInfo;
        }
        if (!$this->isValid()) {
            return "Domain name isn't valid!";
        }
        $whois_server = $this->getWhoisServer()[0];

        // If TLDs have been found
        if (empty($whois_server)) {
            return 'No whois server for this tld in list!';
        }
            // if whois server serve reply over HTTP protocol instead of WHOIS protocol
        if (preg_match('/^https?:\/\//i', $whois_server)) {
            // curl session to get whois reposnse
            $curlHandle = curl_init();
            $url = $whois_server.$this->domain;
            curl_setopt($curlHandle, CURLOPT_URL, $url);
            curl_setopt($curlHandle, CURLOPT_FOLLOWLOCATION, 0);
            curl_setopt($curlHandle, CURLOPT_TIMEOUT, 60);
            curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($curlHandle, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, 0);
            if ($this->proxy) {
                curl_setopt(
                    $curlHandle,
                    CURLOPT_PROXY,
                    $this->proxy['ip']
                );
                curl_setopt(
                    $curlHandle,
                    CURLOPT_PROXYPORT,
                    $this->proxy['port']
                );
            }

            $data = curl_exec($curlHandle);

            if (curl_error($curlHandle)) {
                curl_close($curlHandle);

                return 'Connection error!';
            }
            curl_close($curlHandle);
            $string = strip_tags($data);
        } else {
            // Getting whois information
            $socket = fsockopen(
                $whois_server,
                43,
                $this->socErrno,
                $this->socErrstr,
                $this->socTimeout
            );
            if (!$socket) {
                return 'Connection error! '.$this->socErrno.':'.$this->socErrstr;
            }
            stream_set_blocking($socket, true);
            stream_set_timeout($socket, $this->socTimeout);
            $info = stream_get_meta_data($socket);

            $dom = $this->domain;
            fwrite($socket, "$dom\r\n");

            // Getting string
            $string = '';

            // Checking whois server for .com and .net
            if ($this->TLDs == 'com' || $this->TLDs == 'net') {
                while ((!feof($socket)) && (!$info['timed_out'])) {
                    $line = trim(fgets($socket, 128));

                    $string .= $line;

                    $lineArr = explode(':', $line);

                    if (strtolower($lineArr[0]) == 'whois server') {
                        $whois_server = trim($lineArr[1]);
                    }
                    $info = stream_get_meta_data($socket);
                }
                // Getting whois information
                $socket = fsockopen(
                    $whois_server,
                    43,
                    $this->socErrno,
                    $this->socErrstr,
                    $this->socTimeout
                );
                if (!$socket) {
                    return 'Connection error! '.$this->socErrno.':'.$this->socErrstr;
                }
                stream_set_blocking($socket, true);
                stream_set_timeout($socket, $this->socTimeout);
                $info = stream_get_meta_data($socket);

                // $dom = $this->subDomain . '.' . $this->TLDs;
                fwrite($socket, "$dom\r\n");

                // Getting string
                $string = '';

                while (!feof($socket)) {
                    $string .= fgets($socket, 128);
                }

                // Checking for other tld's
            } else {
                while ((!feof($socket)) && (!$info['timed_out'])) {
                    $string .= fgets($socket, 128);
                    $info = stream_get_meta_data($socket);
                }
            }
            fclose($socket);
        }

        $string_encoding = mb_detect_encoding(
            $string,
            'UTF-8, ISO-8859-1, ISO-8859-15',
            true
        );
        $string_utf8 = mb_convert_encoding(
            $string,
            'UTF-8',
            $string_encoding
        );

        $this->whoisInfo = htmlspecialchars(
            $string_utf8,
            ENT_COMPAT,
            'UTF-8',
            true
        );

        return $this->whoisInfo;
    }

    /**
     * Format whois information into HTML
     * @return string HTML-Formatted whois reply
     */
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
     * Check whether passed domain is available,
     * based on response from whois server.
     * @return bool true for domain available, false for domain registered
     */
    public function isAvailable()
    {
        if ($this->whoisInfo == '') {
            $this->info();
        }

        $whois_string = $this->whoisInfo;
        $not_found_string = '';
        if (isset($this->servers[$this->TLDs][1])) {
            $not_found_string = $this->servers[$this->TLDs][1];
        }

        $whois_string2 = \preg_replace(
            '/'.$this->domain.'/',
            '',
            $whois_string
        );
        $whois_string = \preg_replace('/\s+/', ' ', $whois_string);

        $array = explode(':', $not_found_string);
        if ($array[0] == 'MAXCHARS') {
            return strlen($whois_string2) <= $array[1];
        }

        return preg_match('/'.$not_found_string.'/i', $whois_string);
    }

    /**
     * Check whether domain is valid & has valid tld and matching whois server
     * @return bool True if domain matches constraints
     */
    public function isValid()
    {
        if (isset($this->servers[$this->TLDs][0])
            && strlen($this->servers[$this->TLDs][0]) > 6
        ) {
            $tmp_domain = mb_strtolower($this->subDomain);
            if (preg_match('/^[=]?[a-z0-9\-]+$/', $tmp_domain)
                && !preg_match('/^-|-$/', $tmp_domain)
                // && !preg_match("/--/", $tmp_domain)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get defined whois servers
     * @return array Array of servers
     */
    public function getServers()
    {
        return $this->servers;
    }
}
