<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;

class SyncBillingJob implements ShouldQueue, ShouldBeUnique
{
    public $tries = 3;
    public $timeout = 30;

    public function uniqueId(): string
    {
        return 'billing-sync';
    }

    public function backoff(): array
    {
        return [60, 300];
    }

    public function handle(): void
    {
        Http::timeout(10)->post('https://billing.example.com/sync', ['invoice' => 1]);
        BillingRecord::updateOrCreate(['invoice' => 1], ['synced' => true]);
    }
}
