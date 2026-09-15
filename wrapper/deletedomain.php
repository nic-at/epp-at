#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppDeleteRequest;
use Metaregistrar\EPP\atEppDomain;
use Metaregistrar\EPP\atEppDomainDeleteExtension;

$params = EppHelper::getOpt([
    'domain:',
    'scheduledate:',
]);

EppHelper::checkParams($params);

$domain = $params['domain'] ?? '';

// Ensure required parameters are there
if (!$domain) {
    usage();
}
EppHelper::execute($params, function($connection, $params) {
    $domain = $params['domain'] ?? '';
    $scheduledate = $params['scheduledate'] ?? 'now';

    if ($scheduledate) {
        if (!in_array($scheduledate, ['now', 'expiration'])) {
            fwrite(STDERR, "--scheduledate must be one Parameter out off \"now, expiration\"\n");
            exit(-1);
        }
    }

    $arg = ['pure_delete' => 1];
    if ($scheduledate) {
        $arg['schedule_date'] = $scheduledate;
    }
    $ext = new atEppDomainDeleteExtension($arg);
    $request = new atEppDeleteRequest(new atEppDomain($domain), $ext);
    if ($cltrid = ($params['cltrid'] ?? '')) {
		if (strlen($cltrid) > 64 || strlen($cltrid) < 4 ) {
			fwrite(STDERR, "--cltrid must be between 3 and 64 characters\n");
			exit(-1);
		}
        $request->sessionid = $cltrid;
        $request->addSessionId();
    }

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

 deletedomain  --server <user>:<pass>@<host>:<port> \
               --domain <domain>
               [--scheduledate <now|expiration>]
               [--cltrid <cltrid>]
               [--logdir <directory>]

END;

    exit(-1);
}
