#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppContact;
use Metaregistrar\EPP\atEppVerificationReport;
use Metaregistrar\EPP\atEppUpdateContactExtension;
use Metaregistrar\EPP\atEppUpdateContactRequest;
use Metaregistrar\EPP\atEppContactHandle;
use Metaregistrar\EPP\eppContactPostalInfo;
use Metaregistrar\EPP\eppInfoContactRequest;

$params = EppHelper::getOpt([
    'id:',
    'name:',
    'org::',
    'street:',
    'city:',
    'postalcode:',
    'province::',
    'country:',
    'voice:',
    'email:',
    'type:',
    'verification-report-result:',
    'verification-report-date:',
    'verification-report-method:',
    'verification-report-reference:',
    'verification-report-agent:',
]);

$id = $params['id'] ?? '';
$name = $params['name'] ?? null;
$org = $params['org'] ?? null;
$street = $params['street'] ?? null;
$city = $params['city'] ?? null;
$country = $params['country'] ?? null;
$postalcode = $params['postalcode'] ?? null;
$province = $params['province'] ?? null;
$phone = $params['voice'] ?? null;
$email = $params['email'] ?? null;
$type = $params['type'] ?? null;
$verification_report = [
    'result'    => $params['verification-report-result']    ?? null,
    'date'      => $params['verification-report-date']      ?? null,
    'method'    => $params['verification-report-method']    ?? null,
    'reference' => $params['verification-report-reference'] ?? null,
    'agent'     => $params['verification-report-agent']     ?? null,
];

$uniqueargs = ['name', 'org', 'city', 'postalcode', 'province', 'country', 'phone', 'voice', 'email', 'type'];

foreach ($uniqueargs as $uarg) {
	if (is_array($params[$uarg] ?? null)) {
		echo "\nError: only one --$uarg argument allowed\n";
		usage();
	}
}

// Ensure required parameters are there
if (!$id) {
    usage();
}

// Validate the contact type
if ($type && !in_array($type, ['privateperson', 'organisation', 'role'])) {
	fwrite(STDERR, "--type must be one Parameter out off \"privateperson, organisation, role\"\n");
	exit -1;
}

EppHelper::execute($params, function($connection, $params) {
    $id = $params['id'] ?? '';
    $name = $params['name'] ?? null;
    $org = $params['org'] ?? null;
    $street = $params['street'] ?? null;
    $city = $params['city'] ?? null;
    $country = $params['country'] ?? null;
    $postalcode = $params['postalcode'] ?? null;
    $province = $params['province'] ?? null;
    $phone = $params['voice'] ?? null;
    $email = $params['email'] ?? null;
    $type = $params['type'] ?? null;
    
    // Fetch the existing contact
    $handle = new atEppContactHandle($id);

    $request = EppHelper::prepareRequest($params, eppInfoContactRequest::class, $handle);
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
    if (is_null($province)) $province = $postal->getProvince();
    if (is_null($country)) $country = $postal->getCountrycode();

    if (is_null($type)) $type = $response->getPersonType();

    if (is_null($phone)) $phone = $contact->getVoice();
    if (is_null($email)) $email = $contact->getEmail();

    $verification_report = [
        'result'    => $params['verification-report-result']    ?? null,
        'date'      => $params['verification-report-date']      ?? null,
        'method'    => $params['verification-report-method']    ?? null,
        'reference' => $params['verification-report-reference'] ?? null,
        'agent'     => $params['verification-report-agent']     ?? null,
    ];

    $verification = null;
    if ($verification_report['result'] && $verification_report['date']) {
        $verification = new atEppVerificationReport(
            $verification_report['result'],
            $verification_report['date'],
            $verification_report['method'],
            $verification_report['reference'],
            $verification_report['agent']
        );
    }

    $postalInfo = new eppContactPostalInfo($name, $city, $country, $org, $street, $province, $postalcode);
    $contact = new atEppContact($postalInfo, $type, $email, $phone, null, false,
                                false, false, null, null, $verification);

    $ext = new atEppUpdateContactExtension($contact);

    $request = EppHelper::prepareRequest(
        $params, 
        atEppUpdateContactRequest::class, 
        $handle, null, null, $contact, $ext
    );

    $response = $connection->request($request);

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Contact update failed: ' . $response->getResultMessage() . "\n\n";
    }

    EppHelper::checkAndPrintConditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

});

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
               [--province <province>]
               [--country <country>]
               [--voice <voice>]
               [--email <email>]
               [--type=(privateperson|organisation|role)]
               [--cltrid <cltrid>]
               [--logdir <directory>]
               [--verification-report-result <result>]
               [--verification-report-date <date>]
               [--verification-report-method <method>]
               [--verification-report-reference <reference>]
               [--verification-report-agent <agent>]


    Use --<option> "" do delete the specific value,
    eg. --org "" deletes the stored organisation .

END;

    exit(-1);
}
