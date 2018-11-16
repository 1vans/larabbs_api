<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\Api\AuthorizationRequest;
use App\Http\Requests\Api\SocialAuthorizationRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;


class AuthorizationsController extends Controller
{
    public function store(AuthorizationRequest $request){
        $username = $request->username;
        //验证用户名是否邮箱登录
        filter_var($username, FILTER_VALIDATE_EMAIL) ?
            $credentials['email'] = $username :
            $credentials['phone'] = $username;
        $credentials['password'] = $request->password;

        if (!$token = \Auth::guard('api')->attempt($credentials)) {
            return $this->response->errorUnauthorized(trans('auth.failed'));
        }

        return $this->respondWithToken($token)->setStatusCode(201);
    }
    //第三方登录
    public function socialStore($type,SocialAuthorizationRequest $request){
        if (!in_array($type, ['weixin'])) {
            return $this->response->errorBadRequest();
        }
        $driver = \Socialite::driver($type);
        //1.提交code，获取access_token,getAccessTokenResponse自动设置openid，提交access_token获取个人信息
        //2.提交access_token和openid获取个人信息
        try{
            //提交code
            if($code = $request->code){
                $reponse = $driver->getAccessTokenResponse($code);
                $token = array_get($reponse,'access_token');
            }else{
                //提交access_token 和openid
                $token = $request->access_token;

                if ($type == 'weixin') {
                    $driver->setOpenId($request->openid);
                }
            }
            $oauthUser = $driver->userFromToken($token);

        }catch (\Exception $e){
            return $this->response->errorUnauthorized('参数错误，未获取用户信息');
        }
        switch ($type){
            case 'weixin':
                $unionid = $oauthUser->offsetExists('unionid') ? $oauthUser->offsetGet('unionid') : null;
                if($unionid){
                    $user = User::where('weixin_unionid', $unionid)->first();
                }else{
                    $user = User::where('weixin_openid', $oauthUser->getId())->first();
                }
                // 没有用户，默认创建一个用户
                if (!$user) {
                    $user = User::create([
                        'name' => $oauthUser->getNickname(),
                        'avatar' => $oauthUser->getAvatar(),
                        'weixin_openid' => $oauthUser->getId(),
                        'weixin_unionid' => $unionid,
                    ]);
                }

                break;
        }
        $token = Auth::guard('api')->fromUser($user);
        return $this->respondWithToken($token)->setStatusCode(201);
    }
    //刷新token
    public function update(){
        $token = Auth::guard('api')->refresh();
        return $this->respondWithToken($token);
    }
    //删除token
    public function destroy()
    {
        Auth::guard('api')->logout();
        return $this->response->noContent();
    }
    protected function respondWithToken($token)
    {
        return $this->response->array([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => \Auth::guard('api')->factory()->getTTL() * 60
        ]);
    }

}
