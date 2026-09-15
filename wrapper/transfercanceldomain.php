#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppTransferRequest;
use Metaregistrar\EPP\atEppDomain;

$params = EppHelper::getOpt(['domain:']);

EppHelper::checkParams($params);

$domain = $params['domain'] ?? '';

// Ensure required parameters are there
if (!$domain) {
    usage();
}

EppHelper::execute($params, function($connection, $params) {
    $domain = $params['domain'] ?? '';

    $eppDomain = new atEppDomain($domain);

    $request = EppHelper::prepareRequest(
        $params, 
        atEppTransferRequest::class, 
        atEppTransferRequest::OPERATION_CANCEL, $eppDomain
    );

    $response = $connection->request($request);

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Domain transfer cancellation failed: ' . $response->getResultMessage() . "\n\n";
    }

    EppHelper::checkAndPrintConditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

});

function usage() {
    echo <<<END

usage:

 transfercanceldomain  --server <user>:<pass>@<host>:<port> \
                       --domain <domain>
                       [--cltrid <cltrid>]
                       [--logdir <directory>]

END;

    exit(-1);
}
