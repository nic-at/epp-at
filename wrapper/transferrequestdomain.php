#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppTransferRequest;
use Metaregistrar\EPP\atEppDomain;
use Metaregistrar\EPP\eppException;

$params = EppHelper::getOpt([
    'domain:',
    'registrarinfo:',
    'authinfo:',
]);

EppHelper::checkParams($params);

$domain = $params['domain'] ?? '';
$auth = $params['authinfo'] ?? null;

// Ensure required parameters are there
if (!$domain) {
    usage();
}

// Check registrar info
if (isset($params['registrarinfo'])) {
    echo "Warning: --registrarinfo is deprecated and will be ignored ...\n";
}

EppHelper::execute($params, function($connection, $params) {
    $domain = $params['domain'] ?? '';
    $auth = $params['authinfo'] ?? null;

    $eppDomain = new atEppDomain($domain);
    if ($auth) {
        $eppDomain->setAuthorisationCode($auth);
    }

    $request = EppHelper::prepareRequest(
        $params, 
        atEppTransferRequest::class,
        atEppTransferRequest::OPERATION_REQUEST, 
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
        echo 'Domain transfer request failed: ' . $response->getResultMessage() . "\n\n";
    }

    EppHelper::checkAndPrintConditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

});

function usage() {
    echo <<<END

usage:

 transferrequestdomain  --server <user>:<pass>@<host>:<port> \
                        --domain <domain>
                        [--authinfo \$'<authinfo|token>']
                        [--cltrid <cltrid>]
                        [--logdir <directory>]

Note: The Unix shell intercepts some special characters and tries to
      interpret them (f.e. \$). To pass an authInfo string with special
      characters to the EPP toolkit please encode the authInfo in the format
      \$'<authinfo>'. If you want to use a single quote within the authinfo
      string please escape it with a backslash (\\')

END;

    exit(-1);
}
