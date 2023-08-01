<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;


class UserController extends Controller
{

    public function create(Request $request)
    {
        //
        $access_token = $request->query('access_token');
        $id_info = $request->query('id_info');
        $name = $id_info['name'];
        $email = $id_info['email'];
        $picture = $id_info['picture'];
        $user = User::create([
            'name' => $name,
            'email' => $email,
            'access_token' => $access_token,
            'picture' => $picture,
        ]);

        return response()->json($user);
        // return response()->json(["access_token" => $access_token, "id_info" => $id_info]);
    }



}
