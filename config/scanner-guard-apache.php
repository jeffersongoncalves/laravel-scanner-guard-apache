<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Denylist Path
    |--------------------------------------------------------------------------
    |
    | Relative to base_path(). `IncludeOptional` it from a <Location "/"> in
    | your Apache virtual host. The file is written to a temp file and renamed
    | over the target, so Apache never reads a half-written list, and only when
    | its content changed.
    |
    */
    'path' => env('SCANNER_GUARD_APACHE_PATH', 'storage/app/scanner-guard/apache-denylist.conf'),

    /*
    |--------------------------------------------------------------------------
    | Reload Command
    |--------------------------------------------------------------------------
    |
    | Apache only re-reads an included file on reload. Runs (e.g. "sudo
    | apachectl graceful") only when the file content changed; a non-zero exit
    | or a timeout is logged, never thrown, and the next sync runs it again.
    | Null = don't reload.
    |
    */
    'reload_command' => env('SCANNER_GUARD_APACHE_RELOAD_COMMAND'),

];
