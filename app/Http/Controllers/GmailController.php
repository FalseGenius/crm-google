<?php

namespace App\Http\Controllers;
use Illuminate\Support\Facades\Http;

use Illuminate\Http\Request;

class GmailController extends Controller
{
    //
    public function getEmails(Request $request)
    {
        $user = auth()->user();
        $access_token = $user->access_token;
        $jwt_token = $request->header('Authorization');
        $page_token = $request->query('page_token', '');
        $pageSize = $request->query('page_size', 5);
        $label = $request->query("label", "SENT");

        $url = sprintf("http://127.0.0.1:8000/gmail/messages?page_token=%s&page_size=%s&access_token=%s&jwt_token=%s&label=%s", $page_token, $pageSize, $access_token, $jwt_token, $label);

        // Make a direct HTTP request to the Python API using Laravel's HTTP client
        $response = Http::get($url);

        // Return the response from the Python API
        return $response->body();
    }
}
