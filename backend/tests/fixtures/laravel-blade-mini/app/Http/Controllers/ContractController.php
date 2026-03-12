<?php

namespace App\Http\Controllers;

use App\Services\UserService;

class ContractController extends Controller
{
    // Positive for contract-suggestion (concrete Service)
    public function __construct(private readonly UserService $svc)
    {
    }
}

