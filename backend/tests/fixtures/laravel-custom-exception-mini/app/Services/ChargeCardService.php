<?php

namespace App\Services;

use App\Exceptions\PaymentFailedException;

class ChargeCardService
{
    public function charge(): void
    {
        throw new PaymentFailedException('Charge failed');
    }
}
