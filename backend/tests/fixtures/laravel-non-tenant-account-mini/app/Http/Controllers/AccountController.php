<?php

namespace App\Http\Controllers;

use App\Models\Account;

class AccountController
{
    public function show()
    {
        return Account::query()->first();
    }
}
