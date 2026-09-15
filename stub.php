#!/usr/bin/env php
<?php

$params = getopt('', ['command:']);

if (empty($params['command'])) {
    echo "Usage: php epp-at.phar --command=<command> [args...]\n";
    exit(1);
}

$scriptName = $params['command'];

$scriptDir = __DIR__ . "/wrapper";
$scriptPath = $scriptDir . "/{$scriptName}.php";

if($scriptName == "list") {
    echo "available commands:" . PHP_EOL;
    echo "-- version" . PHP_EOL;
    echo "-- list" . PHP_EOL;
    foreach(scandir($scriptDir) as $path) {
        $matches = null;
        if(is_file("{$scriptDir}/{$path}") && preg_match("/^(.+)\.php$/", $path, $matches) == 1) {
            echo "-- $matches[1]" . PHP_EOL;
        }
    }
    exit(0);
} elseif($scriptName == "version") {
    echo "epp-at - a php based EPP client for the .at registry" . PHP_EOL;
    echo "------" . PHP_EOL;
    if(is_file(__DIR__ . "/VERSION")) {
        echo file_get_contents(__DIR__ . "/VERSION", length: 1024) . PHP_EOL;
    } else {
        echo "Could not find release info!" . PHP_EOL;
    }
    exit(0);
} elseif (!file_exists($scriptPath)) {
    echo "Wrong command given. File does not exist: {$scriptPath}\n";
    exit(1);
}

require $scriptPath;
