<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use JeffersonGoncalves\ScannerGuardApache\ApacheSink;

beforeEach(function () {
    config(['scanner-guard-apache.path' => 'storage/app/scanner-guard/apache-denylist-test.conf']);
    $this->file = storage_path('app/scanner-guard/apache-denylist-test.conf');
});

afterEach(function () {
    File::deleteDirectory(storage_path('app/scanner-guard'));
});

it('writes static entries and bans as Require not ip lines', function () {
    (new ApacheSink)->sync([
        ['ip' => '185.177.72.0/24', 'reason' => 'static', 'expires_at' => null],
        ['ip' => '2001:db8::1', 'reason' => 'scanner_path', 'expires_at' => '2026-11-20T10:00:00+00:00'],
    ]);

    expect(File::get($this->file))->toBe(
        "<RequireAll>\n"
        ."\tRequire all granted\n"
        ."\t# static\n"
        ."\tRequire not ip 185.177.72.0/24\n"
        ."\t# scanner_path, expires 2026-11-20T10:00:00+00:00\n"
        ."\tRequire not ip 2001:db8::1\n"
        ."</RequireAll>\n"
    )->and(File::glob(storage_path('app/scanner-guard/*.tmp')))->toBe([]);
});

it('writes no directive when nothing is banned', function () {
    (new ApacheSink)->sync([]);

    expect(File::get($this->file))->toBe("# nothing banned\n");
});

it('keeps a hostile reason inside its comment', function () {
    (new ApacheSink)->sync([['ip' => '10.20.20.20', 'reason' => "x\nRequire all denied\\", 'expires_at' => null]]);

    expect(File::get($this->file))->toBe("<RequireAll>\n\tRequire all granted\n\t# x_Require_all_denied_\n\tRequire not ip 10.20.20.20\n</RequireAll>\n");
});

it('runs the reload command only when the file content changed', function () {
    Process::fake();
    config(['scanner-guard-apache.reload_command' => 'sudo apachectl graceful']);
    $entries = [['ip' => '10.20.20.23', 'reason' => 'static', 'expires_at' => null]];

    (new ApacheSink)->sync($entries);
    (new ApacheSink)->sync($entries);
    (new ApacheSink)->sync([]);

    Process::assertRanTimes('sudo apachectl graceful', 2);
});

it('logs instead of failing when the reload command fails', function () {
    Process::fake(['*' => Process::result(errorOutput: 'AH00526: Syntax error', exitCode: 1)]);
    Log::spy();
    config(['scanner-guard-apache.reload_command' => 'sudo apachectl graceful']);

    (new ApacheSink)->sync([]);

    Log::shouldHaveReceived('error')->withArgs(fn (string $message, array $context) => $message === 'scanner-guard: Apache reload command failed'
        && str_contains($context['error'], 'AH00526'));
});

it('logs instead of failing when the reload command throws (e.g. a timeout)', function () {
    Process::fake(fn () => throw new RuntimeException('The process exceeded the timeout of 60 seconds.'));
    Log::spy();
    config(['scanner-guard-apache.reload_command' => 'sudo apachectl graceful']);

    (new ApacheSink)->sync([]);

    Log::shouldHaveReceived('error')->withArgs(fn (string $message, array $context) => str_contains($context['error'], 'timeout'));
});

it('runs a failed reload again on the next sync, until it succeeds', function () {
    Process::fake(['*' => Process::sequence()->push(Process::result(exitCode: 1))->push(Process::result())]);
    config(['scanner-guard-apache.reload_command' => 'sudo apachectl graceful']);

    (new ApacheSink)->sync([]); // fails
    (new ApacheSink)->sync([]); // retried
    (new ApacheSink)->sync([]); // up to date

    Process::assertRanTimes('sudo apachectl graceful', 2);
    expect(File::glob(storage_path('app/scanner-guard/*.reload')))->toBe([]);
});

it('is driven by scanner-guard:sync-denylist', function () {
    config([
        'scanner-guard.driver' => 'http', // no database needed: bans come from the (empty) last pull
        'scanner-guard.sinks' => [ApacheSink::class],
        'scanner-guard.ip_blocklist' => ['185.177.72.69', 'not-an-ip'],
    ]);

    $this->artisan('scanner-guard:sync-denylist')->assertSuccessful();

    expect(File::get($this->file))->toBe("<RequireAll>\n\tRequire all granted\n\t# static\n\tRequire not ip 185.177.72.69\n</RequireAll>\n");
});
