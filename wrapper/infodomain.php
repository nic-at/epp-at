#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\eppInfoDomainRequest;
use Metaregistrar\EPP\eppDomain;
use Metaregistrar\EPP\eppStatus;

$params = EppHelper::getOpt([
    'server:',
    'domain:',
]);


EppHelper::checkParams($params);

$domain = $params['domain'] ?? '';

// Ensure required parameters are there
if (!$domain) {
    usage();
}

EppHelper::execute($params, function($connection, $params) {
    $domain = $params['domain'] ?? '';

    $eppDomain = new eppDomain($domain);

    $request = EppHelper::prepareRequest($params, eppInfoDomainRequest::class, $eppDomain);

    $response = $connection->request($request);
    $connection->logout();
    $connection->disconnect();

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Domain info failed: ' . $response->getResultMessage() . "\n\n";
    }

    if ($name = $response->getDomainName()) {
        echo "ATTR: name: $name\n";
    }
    if ($roid = $response->getDomainRoid()) {
        echo "ATTR: roid: $roid\n";
    }
    if ($clid = $response->getDomainClientId()) {
        echo "ATTR: clID: $clid\n";
    }
    if ($crid = $response->getDomainCreateClientId()) {
        echo "ATTR: crID: $crid\n";
    }
    if ($upid = $response->getDomainUpdateClientId()) {
        echo "ATTR: upID: $upid\n";
    }
    if ($date = $response->getDomainCreateDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: crDate: {$date}\n";
    }
    if ($date = $response->getDomainUpdateDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: upDate: {$date}\n";
    }
    if ($date = $response->getDomainExpirationDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: exDate: {$date}\n";
    }
    if ($auth = $response->getDomainAuthInfo()) {
        echo "ATTR: authInfo: $auth\n";
    }
    foreach ($response->getDomainStatuses() as $status) {
        if ($status instanceof eppStatus) {
            $statusDesc = $status->getStatusname();
            if ($statusMessage = $status->getMessage()) {
                $statusDesc .= " // $statusMessage";
            }
            echo "ATTR: status: {$statusDesc}\n";
        } else if (is_string($status)) {
            echo "ATTR: status: $status\n";
        }
    }

    if ($validation = $response->getValidationStatus()) {
        echo "ATTR: Validation Status: " . $validation . "\n";
    }

    echo "\n"; # separate output channels
    echo "ATTR: registrant: " . $response->getDomainRegistrant() . "\n";
    foreach ($response->getDomainContacts() as $contact) {
        if ($contact->getContactType() == 'tech') {
            echo "ATTR: tech: " . $contact->getContactHandle() . "\n";
        }
    }

    if ($ns = $response->getDomainNameservers()) {
        echo "\n"; # separate output channels
        foreach ($ns as $host) {
            echo "ATTR: hostName: " . $host->getHostname() . "\n";
            foreach (($host->getIpAddresses() ?? []) as $ip => $proto) {
                echo "ATTR: hostAddr: {$ip}\n";
            }
        }
    }

    echo "\n"; # separate output channels
    if ($secdns = $response->getKeydata()) {
        echo "  --- DNSSEC ---\n";
        foreach ($secdns as $n) {
            echo "ATTR: keyTag: " . $n->getKeytag() . "\n";
            echo "ATTR: digestType: " . $n->getDigestType() . "\n";
            echo "ATTR: alg: " . $n->getAlgorithm() . "\n";
            echo "ATTR: digest: " . $n->getDigest() . "\n\n";
        }
    }

    echo "\nATTR: clTRID: " . $response->getClientTransactionId() . "\n";
    echo "ATTR: svTRID: " . $response->getServerTransactionId() . "\n";

});

function usage() {
    echo <<<END

usage:

 infodomain   --server <user>:<pass>@<host>:<port>
              --domain <domain>
              [--cltrid <cltrid>]
              [--logdir <directory>]

END;

    exit(-1);
}
