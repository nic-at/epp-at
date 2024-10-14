#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppContact;
use Metaregistrar\EPP\atEppUpdateContactExtension;
use Metaregistrar\EPP\atEppUpdateContactRequest;
use Metaregistrar\EPP\eppException;
use Metaregistrar\EPP\atEppContactHandle;
use Metaregistrar\EPP\eppContactPostalInfo;
use Metaregistrar\EPP\eppInfoContactRequest;

$opts = [
    'server:',
    'id:',
    'name:',
    'org::',
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
$id = $params['id'] ?? '';
$name = $params['name'] ?? null;
$org = $params['org'] ?? null;
$street = $params['street'] ?? null;
$city = $params['city'] ?? null;
$country = $params['country'] ?? null;
$postalcode = $params['postalcode'] ?? null;
$phone = $params['voice'] ?? null;
$fax = $params['fax'] ?? null;
$email = $params['email'] ?? null;
$type = $params['type'] ?? null;

$uniqueargs = ['name', 'org', 'city', 'postalcode', 'country', 'phone', 'voice', 'fax', 'email', 'type'];

foreach ($uniqueargs as $uarg) {
	if (is_array($params[$uarg] ?? null)) {
		echo "\nError: only one --$uarg argument allowed\n";
		usage();
	}
}

// Ensure required parameters are there
if (!($serverstring && $id)) {
    usage();
}

// Validate the contact type
if ($type && !in_array($type, ['privateperson', 'organisation', 'role'])) {
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

    if ($logging) {
        $connection->setLogFile(rtrim($logdir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . date('Y-m-d') . '.log');
    }
    $connected = $connection->connect();
    $connection->setUsername($username);
    $connection->setPassword($password);
    $logged_in = $connection->login();

    // Fetch the existing contact
    $handle = new atEppContactHandle($id);
    $request = new eppInfoContactRequest($handle);
    $response = $connection->request($request);
    $contact = $response->getContact();
    $postal = $contact->getPostalInfo(0);

    if (is_null($name)) $name = $postal->getName();
    if (is_null($org)) $org = $postal->getOrganisationName();
    if (is_null($street)) {
        $street = [];
        for ($i = 0; $i < $postal->getStreetCount(); $i++) {
            $street[] = $postal->getStreet($i);
        }
    }
    if (is_null($city)) $city = $postal->getCity();
    if (is_null($postalcode)) $postalcode = $postal->getZipcode();
    if (is_null($country)) $country = $postal->getCountrycode();

    if (is_null($type)) $type = $response->getPersonType();
    if (is_null($email)) $email = $contact->getEmail();
    if (is_null($phone)) $phone = $contact->getVoice();
    if (is_null($fax)) $fax = $contact->getFax();

    $hideEmail = isset($params['disclose-email']) ? (0 == ($params['disclose-email'] ?? 1)) : $response->getWhoisHideEmail();
    $hidePhone = isset($params['disclose-phone']) ? (0 == ($params['disclose-phone'] ?? 1)) : $response->getWhoisHidePhone();
    $hideFax = isset($params['disclose-fax']) ? (0 == ($params['disclose-fax'] ?? 1)) : $response->getWhoisHideFax();

    $postalInfo = new eppContactPostalInfo($name, $city, $country, $org, $street, null, $postalcode);
    $contact = new atEppContact($postalInfo, $type, $email, $phone, $fax, $hideEmail, $hidePhone, $hideFax);

    // Registry default behaviour disclose=1
    // is something is hidden set the disclose-policy
    $contact->setDisclose(($hideEmail || $hidePhone || $hideFax) ? 0 : 1);

    $ext = new atEppUpdateContactExtension($contact);
    $request = new atEppUpdateContactRequest($handle, null, null, $contact, $ext);
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
        echo 'Contact update failed: ' . $response->getResultMessage() . "\n\n";
    }

    check_and_print_conditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

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

updatecontact  --server <user>:<pass>@<host>:<port> \
               --id <id>
               [--name <name>]
               [--org <org>]
               [--street <street>]
               [--street <street>]
               [--city	<city>]
               [--postalcode <postalcode>]
               [--country <country>]
               [--voice <voice>]
               [--fax <fax>]
               [--email <email>]
               [--disclose-phone <0|1>]
               [--disclose-fax <0|1>]
               [--disclose-email <0|1>]
               [--type=(privateperson|organisation|role)]
               [--cltrid <cltrid>]
               [--logdir <directory>]


    Use --<option> "" do delete the specific value,
    eg. --org "" deletes the stored organisation .

END;

    exit -1;
}
