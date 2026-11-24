<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuardApache;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class ScannerGuardApacheServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-scanner-guard-apache')
            ->hasConfigFile('scanner-guard-apache');
    }
}
