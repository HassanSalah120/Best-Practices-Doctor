<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;

class SyncBillingJob implements ShouldQueue
{
    public function handle(): void
    {
        Http::post('https://billing.example.com/sync', ['invoice' => 1]);
        BillingRecord::create(['invoice' => 1]);
    }
}
