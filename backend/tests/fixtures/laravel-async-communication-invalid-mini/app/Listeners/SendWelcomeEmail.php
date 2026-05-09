<?php

namespace App\Listeners;

class SendWelcomeEmail
{
    public function handle($event)
    {
        Mail::to($event->user)->send($event->mail);
    }
}
