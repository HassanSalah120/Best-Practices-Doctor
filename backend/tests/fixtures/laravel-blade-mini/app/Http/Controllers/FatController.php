<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class FatController extends Controller
{
    public function index(Request $request)
    {
        // Inline validation (positive for missing-form-request)
        $validated = $request->validate([
            "status" => "required|string",
            "name" => "required|string",
        ]);

        // Mass assignment risk (positive for mass-assignment-risk)
        User::create($request->all());

        // Raw SQL usage (positive for raw-sql)
        DB::select("select 1");

        // Positive for no-json-encode-in-controllers (manual JSON encoding inside controller)
        $tmpJson = json_encode(["ok" => true]);

        // Query inside a loop (positive for eager-loading)
        $ids = [1, 2, 3];
        $users = [];
        foreach ($ids as $id) {
            config("app.name");
            $users[] = User::find($id);
        }

        // Multiple queries + extra lines (positive for repository-suggestion / fat-controller)
        $active = User::where("status", "active")->get();
        $pending = User::where("status", "pending")->get();

        // N+1 risk: relation access inside foreach (positive for n-plus-one-risk)
        foreach ($active as $user) {
            $user->posts;
        }

        // Add branching to increase cyclomatic complexity (for repository-suggestion min_complexity)
        if (count($active) > 0) {
            $totalActive = count($active);
        } else {
            $totalActive = 0;
        }

        // Business logic hints (positive for service-extraction)
        $total = $this->calculateTotal($active, $pending) + $totalActive;

        // DTO suggestion: large associative array used as a data carrier (positive for dto-suggestion)
        $payload = [
            "user_id" => 1,
            "email" => "a@example.com",
            "status" => "active",
            "attempts" => 3,
            "ip" => "127.0.0.1",
            "ua" => "fixture",
        ];
        $svc->handle($payload);

        // Static helper abuse (positive for static-helper-abuse)
        Utils::foo();
        Utils::bar();

        // Repeated strings (positive for enum-suggestion)
        $status1 = "pending";
        $status2 = "pending";
        $status3 = "pending";

        return response()->json([
            "validated" => $validated,
            "users" => $users,
            "active" => $active,
            "pending" => $pending,
            "total" => $total,
            "status" => [$status1, $status2, $status3],
        ]);
    }

    private function calculateTotal($a, $b): int
    {
        return count($a) + count($b);
    }

    private function unusedHelper(): void
    {
        // Intentionally unused (fixture for unused-private-method).
    }
}
