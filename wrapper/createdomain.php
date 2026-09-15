#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppCreateDomainRequest;
use Metaregistrar\EPP\atEppContactHandle;
use Metaregistrar\EPP\atEppDomain;
use Metaregistrar\EPP\eppHost;
use Metaregistrar\EPP\eppSecdns;

$params = EppHelper::getOpt([
    'domain:',
    'nameserver:',
    'registrant:',
    'techc:',
    'authinfo:',
    'secdns:',
]);

EppHelper::checkParams($params);

EppHelper::execute($params, function($connection, $params) {
    $domain = $params['domain'] ?? '';
    $nameserver = (array) ($params['nameserver'] ?? []);
    $registrant = $params['registrant'] ?? '';
    $techc = (array) ($params['techc'] ?? []);
    $auth = $params['authinfo'] ?? '';
    
    $secdns = $params['secdns'] ?? '';

    // Ensure required parameters are there
    if (!($domain && $nameserver && $registrant && $techc && $auth)) {
        usage();
    }
    $eppDomain = new atEppDomain($domain);
    $eppDomain->setRegistrant(new atEppContactHandle($registrant, 'reg'));
    foreach ($techc as $handle) {
        $eppDomain->addContact(new atEppContactHandle($handle, 'tech'));
    }
    $eppDomain->setAuthorisationCode($auth);
    foreach ($nameserver as $ns) {
        $host = explode('/', $ns);
        if (count($host) == 1) {
            $eppDomain->addHost(new eppHost($host[0]));
        } else {
            for ($i = 1; $i < count($host); $i++) {
                if ($host[$i] && !filter_var($host[$i], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !filter_var($host[$i], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    fwrite(STDERR, $host[$i] . " is not a valid IPv4/IPv6 Address\n");
                    exit(-1);
                }
                $eppDomain->addHost(new eppHost($host[0], $host[$i]));
            }
        }
    }

    // Check secdns
    if ($secdns) {
        $secdnsarray = array_reduce(explode(',', $secdns), function($carry, $item) {
            [$key, $value] = array_map('trim', explode('=>', $item));
            $carry[$key] = trim($value, "'\"");
            return $carry;
        }, []);
        if (!empty($secdnsarray['keyTag']) && !empty($secdnsarray['digestType']) && !empty($secdnsarray['digest']) && !empty($secdnsarray['alg'])) {
            $eppSecdns = new eppSecdns();
            $eppSecdns->setKeytag($secdnsarray['keyTag']);
            $eppSecdns->setDigestType($secdnsarray['digestType']);
            $eppSecdns->setDigest($secdnsarray['digest']);
            $eppSecdns->setAlgorithm($secdnsarray['alg']);
            $eppDomain->addSecdns($eppSecdns);
        }
    }

    $request = EppHelper::prepareRequest($params, atEppCreateDomainRequest::class, $eppDomain);
    $response = $connection->request($request);
    $connection->logout();
    $connection->disconnect();

    if ($response->Success()) {
        echo 'SUCCESS: ' . $response->getResultCode() . "\n";
    } else {
        echo 'FAILED: ' . $response->getResultCode() . "\n";
        echo 'Domain create failed: ' . $response->getResultMessage() . "\n\n";
    }

    EppHelper::checkAndPrintConditions($response->getExtensionResult());

    echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
    echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

    if ($name = $response->getDomainCreated()) {
        echo "ATTR: name: $name\n";
    }
    if ($date = $response->getDomainCreateDate()) {
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }
        echo "ATTR: crDate: {$date}\n";
    }

});

function usage() {
    echo <<<END

usage:

 createdomain  	--server <user>:<pass>@<host>:<port> \
                --domain <domain>
                --nameserver <nsname>[/<ipaddr>[/<ipaddr>]]
                --nameserver <nsname>[/<ipaddr>[/<ipaddr>]]
                [--nameserver <nsname>[/<ipaddr>[/<ipaddr>]]
                --registrant <registrant>
                --techc <tech-c>
                --authinfo \$'<authinfo>'
                [--secdns "keyTag=>'12346', alg=>3, digestType=>1, digest=>'49FD46E6C4B45C55D4DD'"]
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
