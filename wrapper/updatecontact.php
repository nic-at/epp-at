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
    'org:',
    'street:',
    'city:',
    'postalcode:',
    'province:',
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

// Validate params
$id = $params['id'] ?? '';
$type = $params['type'] ?? null;

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

    // Fetch the existing contact
    $handle = new atEppContactHandle($id);

    $request = EppHelper::prepareRequest($params, eppInfoContactRequest::class, $handle);
    $response = $connection->request($request);
    $contact = $response->getContact();
    $postal = $contact->getPostalInfo(0);

    $oldName = $postal->getName();
    $oldOrg = $postal->getOrganisationName();
    $oldStreet = [];
    for ($i = 0; $i < $postal->getStreetCount(); $i++) {
        $oldStreet[] = $postal->getStreet($i);
    }
    $oldCity = $postal->getCity();
    $oldPostalcode = $postal->getZipcode();
    $oldProvince = $postal->getProvince();
    $oldCountry = $postal->getCountrycode();
    $oldType = $response->getPersonType();
    $oldPhone = $contact->getVoice();
    $oldEmail = $contact->getEmail();

    $name = $params['name'] ?? $oldName;
    $org = $params['org'] ?? $oldOrg;
    $street = $params['street'] ?? $oldStreet;
    $city = $params['city'] ?? $oldCity;
    $country = $params['country'] ?? $oldCountry;
    $postalcode = $params['postalcode'] ?? $oldPostalcode;
    $province = $params['province'] ?? $oldProvince;
    $phone = $params['voice'] ?? $oldPhone;
    $email = $params['email'] ?? $oldEmail;
    $type = $params['type'] ?? $oldType;

    $verification_report = [
        'result'    => $params['verification-report-result']    ?? null,
        'date'      => $params['verification-report-date']      ?? null,
        'method'    => $params['verification-report-method']    ?? null,
        'reference' => $params['verification-report-reference'] ?? null,
        'agent'     => $params['verification-report-agent']     ?? null,
    ];

    $changed =
        $name !== $oldName ||
        $org !== $oldOrg ||
        $street !== $oldStreet ||
        $city !== $oldCity ||
        $postalcode !== $oldPostalcode ||
        $province !== $oldProvince ||
        $country !== $oldCountry ||
        $phone !== $oldPhone ||
        $email !== $oldEmail;

    $persTypeChanged = $type !== $oldType;

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
    $contact = new atEppContact($postalInfo, $type, $email, $phone, null, false, false, false, null, null, $verification);

    $ext = null;
    if ($persTypeChanged || $verification) {
        $ext = new atEppUpdateContactExtension($contact, null, $persTypeChanged);
    }

    $request = EppHelper::prepareRequest(
        $params, 
        atEppUpdateContactRequest::class, 
        $handle, null, null, $changed ? $contact : null, $ext
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
