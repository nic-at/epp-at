#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppCreateDomainRequest;
use Metaregistrar\EPP\eppContactHandle;
use Metaregistrar\EPP\eppDomain;
use Metaregistrar\EPP\eppHost;

$opts = [
    'server:',
    'domain:',
    'nameserver:',
    'registrant:',
    'techc:',
    'authinfo:',
    'secdns:',
    'cltrid:',
    'logdir:',
    'logfile',
    'nossl',
];
$params = getopt('', $opts);

$serverstring = $params['server'] ?? '';
$domain = $params['domain'] ?? '';
$nameserver = (array) ($params['nameserver'] ?? []);
$registrant = $params['registrant'] ?? '';
$techc = (array) ($params['techc'] ?? []);
$secdns = $params['secdns'] ?? '';

// Ensure required parameters are there
if (!($serverstring && $domain && $nameserver && $registrant && $techc)) {
    usage();
}

// Parsing the server string
if (!preg_match('/^([\w\d]+):([\S:@]+)@(\S+):(\d+)$/', $serverstring, $matches)) {
    fwrite(STDERR, "could not parse server string '$serverstring'\n");
    exit -1;
}
[, $username, $password, $hostname, $port] = $matches;

// Check secdns
if ($secdns) {
    $secdnsarray = array_reduce(explode(',', $secdns), function($carry, $item) {
        [$key, $value] = array_map('trim', explode('=>', $item));
        $carry[$key] = trim($value, "'\"");
        return $carry;
    }, []);
}

// Check nossl
if (isset($params['nossl'])) {
    echo "Warning: --nossl is deprecated and will be ignored ...\n";
}

try {
    $logging = false;

    // Check logfile
    if (isset($params['logfile'])) {
        fwrite(STDERR, "The option --logfile is deprecated\n");
        fwrite(STDERR, "use --logdir <directory> instead\n");
        exit -1;
    }

    if ($logdir = ($params['logdir'] ?? '')) {
        $logging = true;
    }

    $connection = new atEppConnection($logging);
    $connection->setHostname($hostname);
    $connection->setPort($port);
    $connection->setTimeout(10);

    if ($logging) {
        $connection->setLogFile(trim($logdir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . date('Y-m-d') . '.log');
    }
    $connection->connect();

    $connection->setUsername($username);
    $connection->setPassword($password);
    $connection->login();

    $eppDomain = new eppDomain($domain);
    $eppDomain->setRegistrant(new eppContactHandle($registrant, 'reg'));
    foreach ($techc as $handle) {
        $eppDomain->addContact(new eppContactHandle($handle, 'tech'));
    }
    $eppDomain->setAuthorisationCode('40tYsiachAb3zi@#');
    foreach ($nameserver as $ns) {
        $host = explode('/', $ns);
        if (count($host) == 1) {
            $eppDomain->addHost(new eppHost($host[0]));
        } else {
            for ($i = 1; $i < count($host); $i++) {
                if ($host[$i] && !filter_var($host[$i], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !filter_var($host[$i], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    fwrite(STDERR, $host[$i] . " is not a valid IPv4/IPv6 Address\n");
                    exit -1;
                }
                $eppDomain->addHost(new eppHost($host[0], $host[$i]));
            }
        }
    }

    $request = new atEppCreateDomainRequest($eppDomain);
    if ($cltrid = ($params['cltrid'] ?? '')) {
		if (strlen($cltrid) > 64 || strlen($cltrid) < 4 ) {
			fwrite(STDERR, "--cltrid must be between 3 and 64 characters\n");
			exit -1;
		}
        $request->sessionid = $cltrid;
    }

    $response = $connection->request($request);
    $connection->logout();
    $connection->disconnect();

    echo $response->SaveXML();

} catch (\Exception $e) {
    echo $e->getMessage();
    exit -1;
}

function usage() {
    echo <<<END

usage:

 createdomain  	--server <user>:<pass>@<host>:<port> \
                --domain <domain>
                --nameserver <nsname>[/<ipaddr>[/<ipaddr>]]
                --nameserver <nsname>[/<ipaddr>[/<ipaddr>]]
                [--nameserver <nsname>[/<ipaddr>[/<ipaddr>]]
                --registrant <registrant>
                --techc <tech-c>
                [--authinfo \$'<authinfo>']
                [--secdns "keyTag=>'12346', alg=>3, digestType=>1, digest=>'49FD46E6C4B45C55D4DD'"]
		[--cltrid <cltrid>]
		[--logdir <directory>]



Note: The Unix shell intercepts some special characters and tries to 
      interpret them (f.e. \$). To pass an authInfo string with special
      characters to the EPP toolkit please encode the authInfo in the format 
      \$'<authinfo>'. If you want to use a single quote within the authinfo 
      string please escape it with a backslash (\\')

END;

    exit -1;
}
