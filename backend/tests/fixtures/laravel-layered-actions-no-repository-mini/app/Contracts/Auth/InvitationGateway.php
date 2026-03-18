<?php

namespace App\Contracts\Auth;

interface InvitationGateway
{
    public function accept(string $token): void;
}
