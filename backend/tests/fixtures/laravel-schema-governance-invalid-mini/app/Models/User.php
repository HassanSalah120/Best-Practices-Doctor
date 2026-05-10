<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $hidden = ['remember_token'];

    protected $appends = ['api_token_preview'];

    protected $casts = [
        'password' => 'hashed',
        'remember_token' => 'encrypted',
    ];
}
