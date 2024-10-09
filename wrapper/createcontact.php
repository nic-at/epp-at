#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppContact;
use Metaregistrar\EPP\atEppCreateContactExtension;
use Metaregistrar\EPP\atEppCreateContactRequest;
use Metaregistrar\EPP\eppException;
use Metaregistrar\EPP\eppContactPostalInfo;

$opts = [
    'server:',
    'name:',
    'org:',
    'street:',
    'city:',
    'postalcode:',
    'country:',
    'voice:',
    'fax:',
    'email:',
    'disclose-phone:',
    'disclose-fax:',
    'disclose-email:',
    'type:',
    'cltrid:',
    'logdir:',
    'logfile',
    'nossl',
];

$params = getopt('', $opts);

$serverstring = $params['server'] ?? '';
$name = $params['name'] ?? '';
$org = $params['org'] ?? null;
$street = $params['street'] ?? '';
$city = $params['city'] ?? '';
$country = $params['country'] ?? '';
$postalcode = $params['postalcode'] ?? '';
$phone = $params['phone'] ?? '';
$fax = $params['fax'] ?? null;
$email = $params['email'] ?? '';
$type = $params['type'] ?? '';

$uniqueargs = ['name', 'org', 'city', 'postalcode', 'country', 'phone', 'voice', 'fax', 'email', 'type'];

foreach ($uniqueargs as $uarg) {
	if (is_array($params[$uarg] ?? null)) {
		echo "\nError: only one --$uarg argument allowed\n";
		usage();
	}
}

// Ensure required parameters are there
if (!($serverstring && $name && $city && $postalcode && $country && $email && $type)) {
    usage();
}

// Validate the contact type
if (!in_array($type, ['privateperson', 'organisation', 'role'])) {
	fwrite(STDERR, "--type must be one Parameter out off \"privateperson, organisation, role\"\n");
	exit -1;
}

// Parsing the server string
if (!preg_match('/^([\w\d]+):([\S:@]+)@(\S+):(\d+)$/', $serverstring, $matches)) {
    fwrite(STDERR, "could not parse server string '$serverstring'\n");
    exit -1;
}
[, $username, $password, $hostname, $port] = $matches;

// Validate the disclose flags
foreach (['email', 'fax', 'phone'] as $disclose) {
    if (!in_array($params["disclose-{$disclose}"] ?? 0, [0, 1])) {
        fwrite(STDERR, "--disclose-{$disclose} has to be set to 0 or 1\n");
		exit -1;
    }
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

    $postalInfo = new eppContactPostalInfo($name, $city, $country, $org, $street, null, $postalcode);
    $contact = new atEppContact($postalInfo, $type, $email, $phone, $fax, 0 == ($params['disclose-email'] ?? 1), 0 == ($params['disclose-phone'] ?? 1), 0 == ($params['disclose-fax'] ?? 1));
    $ext = new atEppCreateContactExtension($contact);

    $request = new atEppCreateContactRequest($contact, $ext);
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
        echo 'Contact create failed: ' . $response->getResultMessage() . "\n\n";
    }

    check_and_print_conditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

    if ($id = $response->getContactId()) {
        echo "ATTR: ID: $id\n";
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

createcontact	--server <user>:<pass>@<host>:<port> \
                --name <name>
                [--org <org>]
                --street <street>
                [--street <street>]
                --city	<city>
                --postalcode <postalcode>
                --country <country>
                [--voice <voice>]
                [--fax <fax>]
                --email <email>
                [--disclose-phone <0|1>]
                [--disclose-fax <0|1>]
                [--disclose-email <0|1>]
                --type=(privateperson|organisation|role)
	            [--cltrid <cltrid>]
                [--logdir <directory>]

END;

    exit -1;
}
