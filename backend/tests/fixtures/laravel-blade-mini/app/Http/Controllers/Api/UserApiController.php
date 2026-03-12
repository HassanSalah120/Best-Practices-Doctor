<?php

namespace App\Http\Controllers\Api;

class UserApiController
{
    // Positive for api-resource-usage: returning raw arrays from API controller.
    public function index()
    {
        return [
            "ok" => true,
            "data" => [
                ["id" => 1],
            ],
        ];
    }
}

