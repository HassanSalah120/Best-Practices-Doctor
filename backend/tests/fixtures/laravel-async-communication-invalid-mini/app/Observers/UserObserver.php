<?php

namespace App\Observers;

class UserObserver
{
    public function updated($user)
    {
        Mail::to($user)->send($mailOne);
        Mail::to($user)->send($mailTwo);
        Notification::send($admins, $firstNotification);
        Notification::send($admins, $secondNotification);
        event(new SomethingChanged($user));
        dispatch(new SyncOne($user));
        dispatch(new SyncTwo($user));
    }
}
