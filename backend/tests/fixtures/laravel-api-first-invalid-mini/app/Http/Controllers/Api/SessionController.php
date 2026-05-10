<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SessionController extends Controller
{
    public function store(Request $request): JsonResponse
    {
        $participants = (array) $request->input('participants', []);
        $score = 0;

        foreach ($participants as $participant) {
            $weight = (int) ($participant['weight'] ?? 1);

            if (($participant['vip'] ?? false) === true) {
                $score += $weight * 3;
            } else {
                $score += $weight;
            }
        }

        if ($score > 10) {
            $status = 'priority';
        } else {
            $status = 'queued';
        }

        return response()->json([
            'score' => $score,
            'status' => $status,
        ]);
    }
}
