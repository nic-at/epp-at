#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppCreateContactExtension;
use Metaregistrar\EPP\atEppCreateContactRequest;

$params = EppHelper::getOpt([
    'name:',
    'org:',
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

EppHelper::checkParams($params);

// Ensure required parameters are there
if(!EppHelper::checkContactData($params)) {
    usage();
}


EppHelper::execute(
    $params, 
    function($connection, $params) {
        $contact = EppHelper::toContact($params);

        $ext = new atEppCreateContactExtension($contact);
        
        $request = EppHelper::prepareRequest($params, atEppCreateContactRequest::class, $contact, $ext);
        $response = $connection->request($request);

        if ($response->Success()) {
            echo 'SUCCESS: ' . $response->getResultCode() . "\n";
        } else {
            echo 'FAILED: ' . $response->getResultCode() . "\n";
            echo 'Contact create failed: ' . $response->getResultMessage() . "\n\n";
        }

        EppHelper::checkAndPrintConditions($response->getExtensionResult());

        echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
        echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

        if ($id = $response->getContactId()) {
            echo "ATTR: ID: $id\n";
        }
    }
);

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
                [--province <province>]
                [--voice <voice>]
                --email <email>
                --type=(privateperson|organisation|role)
	            [--cltrid <cltrid>]
                [--logdir <directory>]
                [--verification-report-result <result>]
                [--verification-report-date <date>]
                [--verification-report-method <method>]
                [--verification-report-reference <reference>]
                [--verification-report-agent <agent>]

END;

    exit(-1);
}
