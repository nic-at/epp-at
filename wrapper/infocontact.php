#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\eppInfoContactRequest;
use Metaregistrar\EPP\atEppContactHandle;
use Metaregistrar\EPP\eppException;

$opts = [
    'server:',
    'id:',
    'cltrid:',
    'logdir:',
    'logfile',
    'nossl',
];

$params = getopt('', $opts);

$serverstring = $params['server'] ?? '';
$id = $params['id'] ?? '';

// Ensure required parameters are there
if (!($serverstring && $id)) {
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

    $handle = new atEppContactHandle($id);

    $request = new eppInfoContactRequest($handle);
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

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Contact info failed: ' . $response->getResultMessage() . "\n\n";
    }

    if ($id = $response->getContactId()) {
        echo "ATTR: ID: $id\n";
    }
    if ($roid = $response->getContactRoid()) {
        echo "ATTR: roid: $roid\n";
    }
    if ($clid = $response->getContactClientId()) {
        echo "ATTR: clID: $clid\n";
    }
    if ($crid = $response->getContactCreateClientId()) {
        echo "ATTR: crID: $crid\n";
    }
    if ($upid = $response->getContactUpdateClientId()) {
        echo "ATTR: upID: $upid\n";
    }
    if ($date = $response->getContactCreateDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: crDate: {$date}\n";
    }
    if ($date = $response->getContactUpdateDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: upDate: {$date}\n";
    }
    foreach ($response->getContactStatus() as $status) {
        echo "ATTR: status: $status\n";
    }

    $contact = $response->getContact();
    for ($i = 0; $i < $contact->getPostalInfoLength(); $i++) {
        $postal = $contact->getPostalInfo($i);
        if ($org = $postal->getOrganisationName()) {
            echo "ATTR: org: $org\n";
        }
        if ($name = $postal->getName()) {
            echo "ATTR: name: $name\n";
        }
        for ($j = 0; $j < $postal->getStreetCount(); $j++) {
            if ($street = $postal->getStreet($j)) {
                echo "ATTR: street: $street\n";
            }
        }
        if ($zip = $postal->getZipcode()) {
            echo "ATTR: pc: $zip\n";
        }
        if ($city = $postal->getCity()) {
            echo "ATTR: city: $city\n";
        }
        if ($country = $postal->getCountrycode()) {
            echo "ATTR: cc: $country\n";
        }
    }
    if ($phone = $contact->getVoice()) {
        echo "ATTR: voice: $phone\n";
    }
    echo "ATTR: email: " . ($contact->getEmail() ?: 'n/a') . "\n";
    if ($fax = $contact->getFax()) {
        echo "ATTR: fax: $fax\n";
    }

    echo "ATTR: disclose: phone " . (1 - $response->getWhoisHidePhone()) . "\n";
    echo "ATTR: disclose: fax " . (1 - $response->getWhoisHideFax()) . "\n";
    echo "ATTR: disclose: email " . (1 - $response->getWhoisHideEmail()) . "\n";

    if ($type = $response->getPersonType()) {
        echo "ATTR: type: $type\n";
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

 infocontact  --server <user>:<pass>@<host>:<port> \
              --id <id>
              [--cltrid <cltrid>]
              [--logdir <directory>]

END;

    exit -1;
}
