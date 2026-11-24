<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuardApache;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use JeffersonGoncalves\ScannerGuard\Contracts\DenylistSink;
use Throwable;

/**
 * Writes the denylist as Apache `Require not ip` lines and reloads Apache when
 * the file changed. Every IP arrives validated.
 */
class ApacheSink implements DenylistSink
{
    public function sync(array $entries): void
    {
        $path = base_path((string) config('scanner-guard-apache.path', 'storage/app/scanner-guard/apache-denylist.conf'));
        $contents = $this->contents($entries);

        // Left behind while a reload failed or never ran, so the next sync tries again.
        $pending = $path.'.reload';

        if (! File::exists($path) || File::get($path) !== $contents) {
            File::ensureDirectoryExists(dirname($path));

            if (! File::exists($pending)) {
                File::put($pending, '');
            }

            // Temp file + rename: an Apache reload mid-write never reads a truncated file.
            $temp = $path.'.'.bin2hex(random_bytes(4)).'.tmp';
            File::put($temp, $contents);
            File::move($temp, $path);
        } elseif (! File::exists($pending)) {
            return;
        }

        if ($this->reload()) {
            File::delete($pending);
        }
    }

    /**
     * @param  list<array{ip: string, reason: string, expires_at: string|null}>  $entries
     */
    protected function contents(array $entries): string
    {
        if ($entries === []) {
            return "# nothing banned\n";
        }

        // Comments on their own line: Apache reads a trailing one as an IP.
        $lines = array_map(function (array $entry): string {
            // A forwarded ban's reason is free text: no newline or trailing \ may reach the config.
            $reason = preg_replace('/[^\w.-]/', '_', $entry['reason']);

            return ($entry['expires_at'] === null ? "\t# {$reason}" : "\t# {$reason}, expires {$entry['expires_at']}")
                ."\n\tRequire not ip {$entry['ip']}";
        }, $entries);

        // `Require not` alone can't succeed, it needs a positive sibling.
        return "<RequireAll>\n\tRequire all granted\n".implode("\n", $lines)."\n</RequireAll>\n";
    }

    /**
     * false when the command failed and must run again.
     */
    protected function reload(): bool
    {
        $command = config('scanner-guard-apache.reload_command');

        if ($command === null || $command === '') {
            return true;
        }

        try {
            $result = Process::run((string) $command);
            $error = $result->failed() ? 'exit '.$result->exitCode().': '.trim($result->errorOutput() ?: $result->output()) : null;
        } catch (Throwable $e) {
            // Timeout or the command can't start: the file is already written, so only report it.
            $error = $e->getMessage();
        }

        if ($error !== null) {
            Log::error('scanner-guard: Apache reload command failed', ['command' => $command, 'error' => $error]);
        }

        return $error === null;
    }
}
