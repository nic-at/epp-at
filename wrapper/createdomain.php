#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppCreateDomainRequest;
use Metaregistrar\EPP\atEppContactHandle;
use Metaregistrar\EPP\atEppDomain;
use Metaregistrar\EPP\eppHost;
use Metaregistrar\EPP\eppSecdns;
use Metaregistrar\EPP\eppException;

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
$auth = $params['authinfo'] ?? '';

// Ensure required parameters are there
if (!($serverstring && $domain && $nameserver && $registrant && $techc && $auth)) {
    usage();
}

// Parsing the server string
if (!preg_match('/^([\w\d]+):([\S:@]+)@(\S+):(\d+)$/', $serverstring, $matches)) {
    fwrite(STDERR, "could not parse server string '$serverstring'\n");
    exit -1;
}
[, $username, $password, $hostname, $port] = $matches;

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
    $connection->setHostname('ssl://' . $hostname);
    $connection->setPort($port);
    $connection->setTimeout(10);
    $connection->setVerifyPeer(false);

    if ($logging) {
        $connection->setLogFile(rtrim($logdir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . date('Y-m-d') . '.log');
    }
    $connected = $connection->connect();
    $connection->setUsername($username);
    $connection->setPassword($password);
    $logged_in = $connection->login();

    $eppDomain = new atEppDomain($domain);
    $eppDomain->setRegistrant(new atEppContactHandle($registrant, 'reg'));
    foreach ($techc as $handle) {
        $eppDomain->addContact(new atEppContactHandle($handle, 'tech'));
    }
    $eppDomain->setAuthorisationCode($auth);
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

    // Check secdns
    if ($secdns) {
        $secdnsarray = array_reduce(explode(',', $secdns), function($carry, $item) {
            [$key, $value] = array_map('trim', explode('=>', $item));
            $carry[$key] = trim($value, "'\"");
            return $carry;
        }, []);
        if (!empty($secdnsarray['keyTag']) && !empty($secdnsarray['digestType']) && !empty($secdnsarray['digest']) && !empty($secdnsarray['alg'])) {
            $eppSecdns = new eppSecdns();
            $eppSecdns->setKeytag($secdnsarray['keyTag']);
            $eppSecdns->setDigestType($secdnsarray['digestType']);
            $eppSecdns->setDigest($secdnsarray['digest']);
            $eppSecdns->setAlgorithm($secdnsarray['alg']);
            $eppDomain->addSecdns($eppSecdns);
        }
    }

    $request = new atEppCreateDomainRequest($eppDomain);
    if ($cltrid = ($params['cltrid'] ?? '')) {
		if (strlen($cltrid) > 64 || strlen($cltrid) < 4 ) {
			fwrite(STDERR, "--cltrid must be between 3 and 64 characters\n");
			exit -1;
		}
        $request->sessionid = $cltrid;
        $request->addSessionId();
    }

    $response = $connection->request($request);
    $connection->logout();
    $connection->disconnect();

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Domain create failed: ' . $response->getResultMessage() . "\n\n";
    }

    check_and_print_conditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

    if ($name = $response->getDomainCreated()) {
        echo "ATTR: name: $name\n";
    }
    if ($date = $response->getDomainCreateDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: crDate: {$date}\n";
    }

} catch (eppException $e) {
    echo $e->getMessage() . "\n";
    check_and_print_conditions(json_decode($e->getReason(), true));
    exit -1;
}

function check_and_print_conditions($conditions) {
    if (!is_array($conditions)) return false;
    foreach ($conditions as $condition) {
        if (!empty($condition['message'])) {
            echo "Msg: {$condition['message']}\n";
        }
        if (!empty($condition['details'])) {
            echo "Details: {$condition['details']}\n";
        }
        echo "\n";
    }
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
                --authinfo \$'<authinfo>'
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
