#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppTransferRequest;
use Metaregistrar\EPP\atEppDomain;
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
    $connection->setVerifyPeer(false);

    if ($logging) {
        $connection->setLogFile(rtrim($logdir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . date('Y-m-d') . '.log');
    }
    $connected = $connection->connect();
    $connection->setUsername($username);
    $connection->setPassword($password);
    $logged_in = $connection->login();

    $eppDomain = new atEppDomain($domain);

    $request = new atEppTransferRequest(atEppTransferRequest::OPERATION_QUERY, $eppDomain);
    if ($cltrid = ($params['cltrid'] ?? '')) {
        if (strlen($cltrid) > 64 || strlen($cltrid) < 4 ) {
            fwrite(STDERR, "--cltrid must be between 3 and 64 characters\n");
            exit -1;
        }
        $request->sessionid = $cltrid;
        $request->addSessionId();
    }

    $response = $connection->request($request);

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";

        if ($name = $response->getDomainName()) printf("ATTR: name: %s\n", $name);
        if ($trStatus = $response->getTransferStatus()) printf("ATTR: trStatus: %s\n", $trStatus);
        if ($reID = $response->getTransferRequestClientId()) printf("ATTR: reID: %s\n", $reID);
        if ($reDate = $response->getTransferRequestDate()) printf("ATTR: reDate: %s\n", ($reTime = strtotime($reDate)) ? $reDate = date('c', $reTime) : $reDate);
        if ($acID = $response->getTransferActionClientId()) printf("ATTR: acID: %s\n", $acID);
        if ($acDate = $response->getTransferActionDate()) printf("ATTR: acDate: %s\n", ($acTime = strtotime($acDate)) ? $acDate = date('c', $acTime) : $acDate);
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Domain transfer request failed: ' . $response->getResultMessage() . "\n\n";
    }

    check_and_print_conditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

    $connection->logout();
    $connection->disconnect();

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

 transferquerydomain   --server <user>:<pass>@<host>:<port> \
                       --domain <domain>
                       [--cltrid <cltrid>]
                       [--logdir <directory>]

END;

    exit -1;
}
