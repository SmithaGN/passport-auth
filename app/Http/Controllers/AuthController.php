<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name' => 'required|max:55',
            'email' => 'email|required|unique:users',
            'password' => 'required|confirmed'
        ]);

        $validatedData['password'] = bcrypt($request->password);

        $user = User::create($validatedData);

        $accessToken = $user->createToken('authToken')->accessToken;

        return response([ 'user' => $user, 'access_token' => $accessToken]);
    }

    public function login(Request $request)
    {
        $loginData = $request->validate([
            'email' => 'email|required',
            'password' => 'required'
        ]);

        if (!auth()->attempt($loginData)) {
            return response(['message' => 'Invalid Credentials']);
        }

        $accessToken = auth()->user()->createToken('authToken')->accessToken;

        return response(['user' => auth()->user(), 'access_token' => $accessToken]);

    }


    public function profile(Request $request)
    {

    	return response()->json(auth()->user());

    }

 	public function changepassword(Request $request)
    {
    	$input = $request->all();

      //$check = User::find($input['user_id']);

    	 $check = User::find(auth()->user()->id);

    	  
      if(isset($check->id)){

          $rules=array(           
            'new_confirm_password' => ['same:new_password'], 
            'new_password' => [
            'required',
            'string',            
            'min:8',             // must be at least 8 characters in length
            'regex:/[a-z]/',     // must contain at least one lowercase letter
           
            'regex:/[0-9]/',      // must contain at least one digit
            'regex:/[@$!%*#?&]/',
          ]
        );      

        $validator=Validator::make($request->all(),$rules);
        if($validator->fails())
        {
            $messages=$validator->messages();
            $errors=$messages->first();

            $result['status'] = false;
            $result['message'] = $errors;
                     
        }else{

          if(Hash::check($input['old_password'], $check->password)){

              $check->password = Hash::make($input['new_password']);
              $check->save();

              $result['success'] = true;
              $result['message'] = 'Password changed successfully';

          }else{
              $result['success'] = false;
              $result['message'] = 'Old password and New password should be same';
          }

        }

      }else{
        $result['success'] = false;
        $result['message'] = 'Invalid User Id';
      }

      return json_encode($result);

    }

    



}