<?php

namespace App\Observers;

class UserObserver
{
    public function updated($user)
    {
        event(new UserProfileChanged($user));
    }
}
