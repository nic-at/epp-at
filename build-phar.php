<?php

$phar = new Phar('epp-at.phar', FilesystemIterator::CURRENT_AS_FILEINFO | FilesystemIterator::KEY_AS_FILENAME, 'epp-at.phar');
$escaped_dir = preg_quote(__DIR__, "/");
$phar->buildFromDirectory(
    __DIR__,
    "/^{$escaped_dir}\/(?:(?:wrapper|vendor|src)\/(.*))|(?:VERSION|LICENSE|README|env.example)/"
);
$phar['stub.php'] = file_get_contents(__DIR__ . '/stub.php');
$phar->setStub("#!/usr/bin/env php\n<?php Phar::mapPhar(); require 'phar://epp-at.phar/stub.php'; __HALT_COMPILER();");

echo "PHAR created: epp-at.phar\n";
