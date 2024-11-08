#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\eppHelloRequest;
use Metaregistrar\EPP\eppException;

$opts = [
    'server:',
    'lang:',
    'ver:',
    'cltrid:',
    'logdir:',
    'logfile',
    'nossl',
];

$params = getopt('', $opts);

$serverstring = $params['server'] ?? '';
$lang = $params['lang'] ?? '';
$ver = $params['ver'] ?? '';

// Ensure required parameters are there
if (!$serverstring) {
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

    $request = new eppHelloRequest();
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
        echo 'Hello failed: ' . $response->getResultMessage() . "\n\n";
    }

    echo "Server Name: " . $response->getServerName() . "\n";
    echo "Server Date: " . $response->getServerDate() . "\n";
    echo "Languages: " . implode(', ', $response->getLanguages()) . "\n";
    echo "Services: " . implode(', ', $response->getServices()) . "\n";
    echo "Extensions: " . implode(', ', $response->getExtensions()) . "\n";
    echo "Versions: " . implode(', ', $response->getVersions()) . "\n";

} catch (eppException $e) {
    echo $e->getMessage() . "\n";
    check_and_print_conditions(json_decode($e->getReason(), true));
    exit -1;
}

if ($lang && $ver) {
    try {
        $response->validateServices($lang, $ver);
        echo "Verification: [OK] Language '$lang' and Version '$ver' are supported by the server!\n";
    } catch (eppException $e) {
        echo "Verification: [Failed] " . $e->getMessage() . "\n";
    }
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

 hello   --server <user>:<pass>@<host>:<port>
              [--lang <language>]
              [--ver <version>]
              [--cltrid <cltrid>]
              [--logdir <directory>]

END;

    exit -1;
}
