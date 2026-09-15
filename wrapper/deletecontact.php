#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppDeleteRequest;
use Metaregistrar\EPP\atEppContactHandle;

$params = EppHelper::getOpt(['id:']);

$id = $params['id'] ?? '';

// Ensure required parameters are there
if (!$id) {
    usage();
}

EppHelper::execute($params, function($connection, $params) {
    $id = $params['id'] ?? '';

    $request = EppHelper::prepareRequest($params, atEppDeleteRequest::class, new atEppContactHandle($id));

    $response = $connection->request($request);

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Contact delete failed: ' . $response->getResultMessage() . "\n\n";
    }

    EppHelper::checkAndPrintConditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

});

function usage() {
    echo <<<END

usage:

 deletecontact  --server <user>:<pass>@<host>:<port> \
                --id <id>
                [--cltrid <cltrid>]
                [--logdir <directory>]

END;

    exit(-1);
}
