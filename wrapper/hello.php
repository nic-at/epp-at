#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\eppHelloRequest;
use Metaregistrar\EPP\eppException;


$params = EppHelper::getOpt([
    'lang:',
    'ver:',
]);

EppHelper::checkParams($params);

EppHelper::execute($params, skip_login: true, fn: function($connection, $params) {
    $request = EppHelper::prepareRequest($params, eppHelloRequest::class);

    $response = $connection->request($request);
    $connection->disconnect();

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Hello failed: ' . $response->getResultMessage() . "\n\n";
    }

    echo "Server Name: " . $response->getServerName() . "\n";
    echo "Server Date: " . $response->getServerDate() . "\n";
    echo "Languages: " . implode(', ', $response->getLanguages()) . "\n";
    echo "Services: " . implode(', ', $response->getServices()) . "\n";
    echo "Extensions: " . implode(', ', $response->getExtensions()) . "\n";
    echo "Versions: " . implode(', ', $response->getVersions()) . "\n";


    $lang = $params['lang'] ?? '';
    $ver = $params['ver'] ?? '';
    if ($lang && $ver) {
        try {
            $response->validateServices($lang, $ver);
            echo "Verification: [OK] Language '$lang' and Version '$ver' are supported by the server!\n";
        } catch (eppException $e) {
            echo "Verification: [Failed] " . $e->getMessage() . "\n";
        }
    }
});

function usage() {
    echo <<<END

usage:

 hello   --server [<user>:<pass>@]<host>[:<port>]
              [--lang <language>]
              [--ver <version>]
              [--cltrid <cltrid>]
              [--logdir <directory>]

END;

    exit(-1);
}
