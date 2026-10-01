#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\eppInfoContactRequest;
use Metaregistrar\EPP\atEppContactHandle;
use Metaregistrar\EPP\eppException;
use Metaregistrar\EPP\eppRequest;

$params = EppHelper::getOpt(['id:']);

$id = $params['id'] ?? '';

// Ensure required parameters are there
if (!$id) {
    usage();
}

EppHelper::execute($params, function($connection, $params) {
    $id = $params['id'] ?? '';
    $handle = new atEppContactHandle($id);

    $request = EppHelper::prepareRequest($params, eppInfoContactRequest::class, $handle);

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
        if ($sp = $postal->getProvince()) {
            echo "ATTR: sp: $sp\n";
        }
        if ($country = $postal->getCountrycode()) {
            echo "ATTR: cc: $country\n";
        }
    }
    if ($phone = $contact->getVoice()) {
        echo "ATTR: voice: $phone\n";
    }
    echo "ATTR: email: " . ($contact->getEmail() ?: 'n/a') . "\n";

    if ($type = $response->getPersonType()) {
        echo "ATTR: type: $type\n";
    }

    if ($validation = $response->getValidationReport()) {
        echo "  --- Verification Report ---\n";
        if ($validation->getResult()) {
            echo "ATTR: Result: " . $validation->getResult() . "\n";
        }
        if ($validation->getVerificationDate()) {
            echo "ATTR: Verification Date: " . $validation->getVerificationDate() . "\n";
        }
        if ($validation->getMethod()) {
            echo "ATTR: Method: " . $validation->getMethod() . "\n";
        }
        if ($validation->getReference()) {
            echo "ATTR: Reference: " . $validation->getReference() . "\n";
        }
        if ($validation->getAgent()) {
            echo "ATTR: Agent: " . $validation->getAgent() . "\n";
        }
        if ($validation->getReceivedDate()) {
            echo "ATTR: Received Date: " . $validation->getReceivedDate() . "\n";
        }
        if ($validation->getclID()) {
            echo "ATTR: Client ID: " . $validation->getclID() . "\n";
        }
        if ($response->getValidationStatus()) {
            echo "ATTR: Status: " . $response->getValidationStatus(). "\n";
        }
        if ($response->getValidationActionDate()) {
            echo "ATTR: Action Date: " . $response->getValidationActionDate() . "\n";
        }
    }

    echo "\nATTR: clTRID: " . $response->getClientTransactionId() . "\n";
    echo "ATTR: svTRID: " . $response->getServerTransactionId() . "\n";

});

function usage() {
    echo <<<END

usage:

 infocontact  --server <user>:<pass>@<host>:<port> \
              --id <id>
              [--cltrid <cltrid>]
              [--logdir <directory>]

END;

    exit(-1);
}
