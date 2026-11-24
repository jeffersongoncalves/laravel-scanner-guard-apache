<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuardApache\Tests;

use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;
use JeffersonGoncalves\ScannerGuardApache\ScannerGuardApacheServiceProvider;
use JeffersonGoncalves\VisitorFingerprint\VisitorFingerprintServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            VisitorFingerprintServiceProvider::class,
            ScannerGuardServiceProvider::class,
            ScannerGuardApacheServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('cache.default', 'array');
    }
}
