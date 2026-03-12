<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SecurityBadController extends Controller
{
    public function run(Request $request)
    {
        // Positive fixtures for security rules (Phase 9).

        $code = $request->input("code");
        eval($code);

        assert("phpinfo();");

        preg_replace("/.*/e", "phpinfo()", $code);

        $payload = $request->input("payload");
        $x = unserialize($payload);

        $cmd = $request->input("cmd");
        exec($cmd);

        $id = $request->input("id");
        DB::select("select * from users where id = $id");
        User::whereRaw("id = $id")->get();

        return response()->json(["ok" => true, "x" => $x]);
    }
}

