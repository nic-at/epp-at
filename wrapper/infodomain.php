#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\eppInfoDomainRequest;
use Metaregistrar\EPP\eppDomain;
use Metaregistrar\EPP\eppException;

$opts = [
    'server:',
    'domain:',
    'cltrid:',
    'logdir:',
    'logfile',
    'nossl',
];

$params = getopt('', $opts);

$serverstring = $params['server'] ?? '';
$domain = $params['domain'] ?? '';

// Ensure required parameters are there
if (!($serverstring && $domain)) {
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

    if ($logging) {
        $connection->setLogFile(rtrim($logdir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . date('Y-m-d') . '.log');
    }
    $connected = $connection->connect();
    $connection->setUsername($username);
    $connection->setPassword($password);
    $logged_in = $connection->login();

    $eppDomain = new eppDomain($domain);

    $request = new eppInfoDomainRequest($eppDomain);
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
        echo 'Domain info failed: ' . $response->getResultMessage() . "\n\n";
    }

    if ($name = $response->getDomainName()) {
        echo "ATTR: name: $name\n";
    }
    if ($roid = $response->getDomainRoid()) {
        echo "ATTR: roid: $roid\n";
    }
    if ($clid = $response->getDomainClientId()) {
        echo "ATTR: clID: $clid\n";
    }
    if ($crid = $response->getDomainCreateClientId()) {
        echo "ATTR: crID: $crid\n";
    }
    if ($upid = $response->getDomainUpdateClientId()) {
        echo "ATTR: upID: $upid\n";
    }
    if ($date = $response->getDomainCreateDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: crDate: {$date}\n";
    }
    if ($date = $response->getDomainUpdateDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: upDate: {$date}\n";
    }
    if ($date = $response->getDomainExpirationDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: exDate: {$date}\n";
    }
    if ($auth = $response->getDomainAuthInfo()) {
        echo "ATTR: authInfo: $auth\n";
    }
    foreach ($response->getDomainStatuses() as $status) {
        echo "ATTR: status: $status\n";
    }

    echo "\n"; # separate output channels
    echo "ATTR: registrant: " . $response->getDomainRegistrant() . "\n";
    foreach ($response->getDomainContacts() as $contact) {
        if ($contact->getContactType() == 'tech') {
            echo "ATTR: tech: " . $contact->getContactHandle() . "\n";
        }
    }

    if ($ns = $response->getDomainNameservers()) {
        echo "\n"; # separate output channels
        foreach ($ns as $host) {
            echo "ATTR: hostName: " . $host->getHostname() . "\n";
            foreach (($host->getIpAddresses() ?? []) as $ip => $proto) {
                echo "ATTR: hostAddr: {$ip}\n";
            }
        }
    }

    echo "\n"; # separate output channels
    if ($secdns = $response->getKeydata()) {
        echo "  --- DNSSEC ---\n";
        foreach ($secdns as $n) {
            echo "ATTR: keyTag: " . $n->getKeytag() . "\n";
            echo "ATTR: digestType: " . $n->getDigestType() . "\n";
            echo "ATTR: alg: " . $n->getAlgorithm() . "\n";
            echo "ATTR: digest: " . $n->getDigest() . "\n\n";
        }
    }

    echo "\nATTR: clTRID: " . $response->getClientTransactionId() . "\n";
    echo "ATTR: svTRID: " . $response->getServerTransactionId() . "\n";

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

 infodomain   --server <user>:<pass>@<host>:<port>
              --domain <domain>
              [--cltrid <cltrid>]
              [--logdir <directory>]

END;

    exit -1;
}
