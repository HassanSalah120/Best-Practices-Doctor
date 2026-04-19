<?php

use Illuminate\Support\Facades\Broadcast;

Broadcast::channel('orders.{order}', fn ($user, $order) => true);
