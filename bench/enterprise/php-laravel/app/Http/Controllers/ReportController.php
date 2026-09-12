<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ReportController extends Controller
{
    // VULNERABLE: command execution from user input
    public function export(Request $request)
    {
        $file = $request->input('file');
        system("tar -czf /tmp/export.tar.gz {$file}");
        return response()->json(['ok' => true]);
    }

    // VULNERABLE: code execution from user input
    public function render(Request $request)
    {
        $tpl = $request->input('tpl');
        eval("return {$tpl};");
        return response()->json(['ok' => true]);
    }

    // SAFE: escaped output
    public function preview(Request $request)
    {
        $html = $request->input('html');
        return view('preview', ['content' => htmlspecialchars($html)]);
    }
}
