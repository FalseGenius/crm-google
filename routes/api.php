<?php


use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Http;
use Illuminate\Http\Request;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\GmailController;

Route::get('/oauth/authorize', function () {
    return redirect("http://127.0.0.1:8000/oauth/google/authorize");
});

Route::get('/oauth/response', [AuthController::class, "create"]);

Route::group(['middleware' => ['auth:api']], function () {
    Route::post('/api/save_token', [AuthController::class, 'saveToken']);
    // Route::get('/emails', function (Request $request) {
    //     $user = auth()->user();
    //     $access_token = $user->access_token;
    //     $jwt_token = $request->header('Authorization');
    //     $page_token = $request->query('page_token', '');
    //     $pageSize = $request->query('page_size', 5);
    //     $label = $request->query("label", "SENT");
    //     $url = sprintf("http://127.0.0.1:8000/gmail/messages?page_token=%s&page_size=%s&access_token=%s&jwt_token=%s&label=%s",$page_token, $pageSize, $access_token, $jwt_token, $label);
    //     return redirect($url);
    // });

    Route::get('/emails', [GmailController::class, "getEmails"]);

    Route::get('/email/{email_id}', function ($message_id) {
        $user = auth()->user();
        $access_token = $user->access_token;
        $url = sprintf("http://127.0.0.1:8000/gmail/message?message_id=%s&access_token=%s", $message_id, $access_token);
        return redirect($url);
    });

    Route::post('/dispatchMail', function (Request $request) {
        $user = auth()->user();
        $access_token = $user->access_token;
        $url = sprintf("http://127.0.0.1:8000/gmail/send?access_token=%s", $access_token);
        $response = Http::asJson()->post($url, [
            'to' => $request->input('to'),
            'subject' => $request->input('subject'),
            'body' => $request->input('body'),
        ]);
        return $response->json();
    });
});
