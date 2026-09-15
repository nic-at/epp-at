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
        atEppTransferRequest::OPERATION_QUERY, 
        $eppDomain
    );

    $response = $connection->request($request);

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";

        if ($name = $response->getDomainName()) printf("ATTR: name: %s\n", $name);
        if ($trStatus = $response->getTransferStatus()) printf("ATTR: trStatus: %s\n", $trStatus);
        if ($reID = $response->getTransferRequestClientId()) printf("ATTR: reID: %s\n", $reID);
        if ($reDate = $response->getTransferRequestDate()) printf("ATTR: reDate: %s\n", ($reTime = strtotime($reDate)) ? $reDate = date('c', $reTime) : $reDate);
        if ($acID = $response->getTransferActionClientId()) printf("ATTR: acID: %s\n", $acID);
        if ($acDate = $response->getTransferActionDate()) printf("ATTR: acDate: %s\n", ($acTime = strtotime($acDate)) ? $acDate = date('c', $acTime) : $acDate);
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Domain transfer query failed: ' . $response->getResultMessage() . "\n\n";
    }

    EppHelper::checkAndPrintConditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

});

function usage() {
    echo <<<END

usage:

 transferquerydomain   --server <user>:<pass>@<host>:<port> \
                       --domain <domain>
                       [--cltrid <cltrid>]
                       [--logdir <directory>]

END;

    exit(-1);
}
