<?php

use Illuminate\Support\Facades\Broadcast;

Broadcast::channel('orders.{order}', function ($user, $order) {
    return $user->id === $order->user_id;
});
