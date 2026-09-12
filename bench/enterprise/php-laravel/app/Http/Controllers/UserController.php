<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Models\User;

class UserController extends Controller
{
    // VULNERABLE: raw SQL interpolation of user input
    public function search(Request $request)
    {
        $q = $request->input('q');
        $users = DB::select("SELECT * FROM users WHERE name LIKE '%{$q}%'");
        return response()->json($users);
    }

    // VULNERABLE: raw where with user input (query builder bypass)
    public function filter(Request $request)
    {
        $col = $request->input('col');
        $rows = DB::table('users')->whereRaw("{$col} = 1")->get();
        return response()->json($rows);
    }

    // SAFE: Eloquent ORM (parameterized)
    public function show(Request $request)
    {
        $id = $request->input('id');
        $user = User::where('id', $id)->first();
        return response()->json($user);
    }
}
