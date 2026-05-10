<?php

namespace App\Services\Auth;

use App\Contracts\Auth\InvitationGateway;

final class InvitationService
{
    public function __construct(
        private readonly InvitationGateway $gateway,
    ) {
    }

    public function accept(string $token): void
    {
        $this->gateway->accept($token);
    }
}
