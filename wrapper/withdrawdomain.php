#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppWithdrawRequest;
use Metaregistrar\EPP\atEppDomain;

$params = EppHelper::getOpt([
    'domain:',
    'deletezone',
]);

$domain = $params['domain'] ?? '';

// Ensure required parameters are there
if (!$domain) {
    usage();
}

EppHelper::execute($params, function($connection, $params) {
    $domain = $params['domain'] ?? '';
    $zd = isset($params['deletezone']);
    $request = EppHelper::prepareRequest(
        $params,
        atEppWithdrawRequest::class,
        new atEppDomain($domain), 
        $zd
    );

    $response = $connection->request($request);

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Domain delete failed: ' . $response->getResultMessage() . "\n\n";
    }

    EppHelper::checkAndPrintConditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";
});

function usage() {
    echo <<<END

usage:

 withdrawdomain --server <user>:<pass>@<host>:<port> \
                --domain <domain>
                [--deletezone ]
                [--cltrid <cltrid>]
                [--logdir <directory>]

END;

    exit(-1);
}
