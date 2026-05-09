<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class TopicController extends Controller
{
    public function index(Request $request)
    {
        [$status, $search] = $this->resolveIndexFilters($request);

        return response()->json([
            'status' => $status,
            'search' => $search,
        ]);
    }

    private function resolveIndexFilters(Request $request): array
    {
        $status = $request->string('status')->value() ?: 'all';
        $search = $request->string('q')->trim()->value();

        return [$status, $search];
    }
}
