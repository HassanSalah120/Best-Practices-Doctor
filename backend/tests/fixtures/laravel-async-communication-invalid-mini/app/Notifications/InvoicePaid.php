<?php

namespace App\Notifications;

use Illuminate\Notifications\Notification;

class InvoicePaid extends Notification
{
    public function toMail($notifiable)
    {
        return new \stdClass();
    }
}
