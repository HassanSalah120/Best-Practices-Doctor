<?php

namespace App\Http\Controllers;

use App\Actions\Auth\AcceptInvitationAction;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class InvitationController
{
    public function __construct(
        private readonly AcceptInvitationAction $acceptInvitation,
    ) {
    }

    public function store(Request $request): RedirectResponse
    {
        $token = (string) $request->input('token');

        $this->acceptInvitation->execute($token);

        return redirect()->route('dashboard');
    }
}
