<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Http;
use Illuminate\Http\Request;
use App\Http\Controllers\AuthController;

Route::get('/oauth/authorize', function () {
    // $response = Http::get('http://127.0.0.1:8000/oauth/google/authorize');
    return redirect("http://127.0.0.1:8000/oauth/google/authorize");
    // return redirect()->away($response);
});

// Route::get('/oauth/response', function (Request $request) {
//     $access_token = $request->query('access_token');
//     $id_info = $request->query('id_info');
    
//     // Call the /gmail/messages endpoint in FastAPI backend
//     $response = Http::withHeaders(['Authorization' => 'Bearer ' . $access_token])
//         ->get('http://127.0.0.1:8000/gmail/messages');

//     // Check if the request was successful
//     if ($response->successful()) {
//         // Save the fetched messages to MongoDB here (implementation not shown)
        
//         // Return the fetched messages as the response
//         $messages = $response->json();
//         return response()->json($messages);
//     } else {
//         // Handle the case when the request to /gmail/messages failed
//         return response()->json(['error' => 'Failed to fetch Gmail messages'], 500);
//     }
// });

// Route::get('/oauth/response', function (Request $request) {
//     $access_token = $request->query('access_token');
//     $id_info = $request->query('id_info');

//     return response()->json(["access_token" => $access_token, "id_info" => $id_info]);
// });

Route::get('/oauth/response', [AuthController::class, "create"]);
