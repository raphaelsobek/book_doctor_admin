<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Dotenv\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Api\User;
use App\Models\User as ModelsUser;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator as FacadesValidator;

class AuthController extends Controller
{

    /* method to login user using an Api
      *@params  Request $request
      @return User
    **/
    public function login(Request  $request){

       try {
        $input=$request->all();
        $validator = FacadesValidator::make($input,[
          "email"=> "required|email",
          "password"=> "required",
        ]);
        if($validator ->fails()){
           return response()->json([
          "status"=>false,
          "message"=>"Erreur de validation",
          "errors"=>$validator->errors(),

        ],422 ,);
        }
       if(!Auth::attempt($request->only(['email','password']))){
        return response()->json([
          "status"=>false,
          "message"=>"Email ou Mot de passe incorrect",
          "errors"=>$validator->errors(),

        ],401 ,);
       }
        $user = ModelsUser::where('email',$request->email)->first();
        return response()->json([
          "status"=>true,
          "message"=>"Utilisateur connecte avec succes",
          "data"=>[
            "token"=>$user->createToken('auth_user')->plainTextToken,
             "toke_type"=>"Bearer",
          ],

        ]);
       } catch (\Throwable $th) {
        //throw $th;
        return response()->json([
          "status"=>false,
          "message"=>$th->getMessage(),

        ],500 ,);
       }

    }

    /* method to register user using an Api
      *@params  Request $request
      @return User
    **/
    public function register(Request  $request){
        
       $input=$request->all();
       //dd($input);
       try {
        $input=$request->all();
        $validator = FacadesValidator::make($input,[
          "name"=> "required",
          "email"=> "required|email|unique:users,email",
          "password"=> "required|confirmed",
          "password_confirmation"=> "required",
        ]);
        if($validator ->fails()){ 
           return response()->json([
          "status"=>false,
          "message"=>"Erreur de validation",
          "errors"=>$validator->errors(),

        ],422 ,);
        }

        $input['password']=Hash::make($request->password);
        $user = ModelsUser::create($input);

        return response()->json([
          "status"=>true,
          "message"=>"Utilisateur cree avec succes",
          "data"=>[
            "token"=>$user->createToken('auth_user')->plainTextToken,
             "toke_type"=>"Bearer",
          ],

        ]);
       } catch (\Throwable $th) {
        //throw $th;
        return response()->json([
          "status"=>false,
          "message"=>$th->getMessage(),

        ],500 ,);
       }
    }

    public function profile(Request $request){
    
      return response()->json([
        "status"=>true,
        "message"=>"Profil Utilisateur",
        "data"=> $request->user(),

      ]);

    }

    public function edit(Request $request){
      try {
        $input=$request->all();
        $validator = FacadesValidator::make($input,[
          "email"=> "required|email|unique:users,email",
          
        ]);
        if($validator ->fails()){
           return response()->json([
          "status"=>false,
          "message"=>"Erreur de validation",
          "errors"=>$validator->errors(),

        ],422 ,);
        }
       $request->user()->update($input);
        return response()->json([
          "status"=>true,
          "message"=>"Utilisateur modifie avec succes",
          "data"=>$request->user(),

        ]);
       } catch (\Throwable $th) {
        //throw $th;
        return response()->json([
          "status"=>false,
          "message"=>$th->getMessage(),

        ],500 ,);
       }
    }

    public function updatePassword(Request $request){
      try {
        $input=$request->all();
        $validator = FacadesValidator::make($input,[
          "old_password"=> "required",
          "new_password"=> "required|confirmed",
          
        ]);
        if($validator ->fails()){
           return response()->json([
          "status"=>false,
          "message"=>"Erreur de validation",
          "errors"=>$validator->errors(),

        ],422 ,);
        }
        if(!Hash::check($input['old_password'],$request->user()->password)){
          return response()->json([
            "status"=>false,
            "message"=>"l'ancien mot de passe est incorrect",
          ],401 ,);
        }
       $input['password']=Hash::make($input['new_password']);
       $request->user()->update($input);
        return response()->json([
          "status"=>true,
          "message"=>"mot de passe modifie avec succes",
          "data"=>$request->user(),

        ]);
       } catch (\Throwable $th) {
        //throw $th;
        return response()->json([
          "status"=>false,
          "message"=>$th->getMessage(),

        ],500 ,);
       }
    }
}
