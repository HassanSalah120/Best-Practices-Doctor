<?php

namespace App\Actions\Auth;

use App\Services\Auth\InvitationService;

final class AcceptInvitationAction
{
    public function __construct(
        private readonly InvitationService $invitations,
    ) {
    }

    public function execute(string $token): void
    {
        $this->invitations->accept($token);
    }
}
