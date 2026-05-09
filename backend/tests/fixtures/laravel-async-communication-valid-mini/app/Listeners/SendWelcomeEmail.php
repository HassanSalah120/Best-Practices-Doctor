<?php

namespace App\Listeners;

use Illuminate\Contracts\Queue\ShouldQueue;

class SendWelcomeEmail implements ShouldQueue
{
    public function handle($event)
    {
        Mail::to($event->user)->send($event->mail);
    }
}
