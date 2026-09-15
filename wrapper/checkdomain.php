#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\eppCheckDomainRequest;

$params = EppHelper::getOpt(['domain:']);

EppHelper::checkParams($params);

$domain = $params['domain'] ?? [];

// Ensure required parameters are there
if (!$domain) {
    usage();
}

EppHelper::execute(
    $params,
    function($connection, $params) use($domain) {
        $request = EppHelper::prepareRequest($params, eppCheckDomainRequest::class, (array) $domain);
        $response = $connection->request($request);

        if ($response->Success()) {
            echo 'SUCCESS: ' . $response->getResultCode() . "\n";

            foreach ($response->getCheckedDomains() as $checkeddomain) {
                $exists = $checkeddomain['available'] ? 'NO' : 'YES';
                echo "ATTR: {$checkeddomain['domainname']} {$exists} {$checkeddomain['reason']}\n";
            }

        } else {
            echo 'FAILED: ' . $response->getResultCode() . "\n";
            echo 'Domain check failed: ' . $response->getResultMessage() . "\n\n";
        }

        echo "\nATTR: clTRID: " . $response->getClientTransactionId() . "\n";
        echo "ATTR: svTRID: " . $response->getServerTransactionId() . "\n";
    }
);

function usage() {
    echo <<<END

usage:

 checkdomain   --server <user>:<pass>@<host>:<port> \
               --domain <domain>
               [--cltrid <cltrid>]
               [--logdir <directory>]

END;

    exit(-1);
}
