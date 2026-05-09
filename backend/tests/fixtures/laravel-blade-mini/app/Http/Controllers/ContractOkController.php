<?php

namespace App\Http\Controllers;

use App\Contracts\UserServiceInterface;

class ContractOkController extends Controller
{
    // Negative: already depends on an interface
    public function __construct(private readonly UserServiceInterface $svc)
    {
    }
}

