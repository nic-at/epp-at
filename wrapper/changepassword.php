#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\eppLoginRequest;
use Metaregistrar\EPP\eppException;

$opts = [
    'server:',
    'newpassword:',
    'cltrid:',
    'logdir:',
    'logfile',
    'nossl',
];

$params = getopt('', $opts);

$serverstring = $params['server'] ?? '';
$newpassword = $params['newpassword'] ?? [];

// Ensure required parameters are there
if (!($serverstring && $newpassword)) {
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

// Check password length
if (!xml_is_token($newpassword, 8, 16)) {
    fwrite(STDERR, " --newpassword must be between 8 and 16 characters\n");
    exit -1;
};

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
    $connection->setNewPassword($newpassword);
    $connected = $connection->login();

    if ($connected) {
        echo "SUCCESS: The EPP-Password has been changed\n\n";
    }

    $connection->logout();
    $connection->disconnect();

} catch (eppException $e) {
    echo 'FAILED: ' . $e->getCode() . "\n";
    echo 'Password change failed: ' . $e->getMessage() . "\n\n";
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

function xml_is_token($what, $min = null, $max = null) {
    // Return false if $what is not defined
    if (empty($what)) {
        return false;
    }

    // Return false if $what is an array or an object
    if (is_array($what) || is_object($what)) {
        return false;
    }

    // Return false if $what contains invalid characters
    if (preg_match('/[\r\n\t]/', $what)) {
        return false;
    }

    // Return false if $what starts or ends with whitespace, or has consecutive spaces
    if (preg_match("/^\s/", $what) || preg_match("/\s$/", $what) || preg_match("/\s\s/", $what)) {
        return false;
    }

    // Check the length of $what
    $l = strlen($what);
    if (!is_null($min) && $l < $min) {
        return false;
    }
    if (!is_null($max) && $l > $max) {
        return false;
    }

    return true;
}

function usage() {
    echo <<<END

usage:

 changepassword   --server <user>:<pass>@<host>:<port>
                  --newpassword <password>
                  [--cltrid <cltrid>]
                  [--logdir <directory>]
 Note: The Unix shell intercepts some special characters and tries to
       interpret them (f.e. \$). To pass a password string with special
       characters to the EPP toolkit please encode the password in the format
       \$'<password>'. If you want to use a single quote within the password
       string please escape it with a backslash (\\')

END;

    exit -1;
}
