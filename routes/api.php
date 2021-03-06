<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
$api = app('Dingo\Api\Routing\Router');
$api->version('v1',[
    'namespace' => 'App\Http\Controllers\Api',
    //设置返回数据格式,绑定bindings 中间键修改返回码，设置本地化
    'middleware' => ['serializer:array','bindings','change-locale']
], function($api) {
    $api->group([
        'middleware' => 'api.throttle',
        //设置访问频率
        'limit' => config('api.rate_limits.sign.limit'),
        'expires' => config('api.rate_limits.sign.limit'),
    ],function ($api){
        // 游客可以访问的接口
        //短信验证码
        $api->post('verificationCodes','VerificationCodesController@store')->name('api.verificationCode.store');
        //用户注册
        $api->post('users','UsersController@store')->name('api.users.store');
        //图片验证码
        $api->post('captchas','CaptchasController@store')->name('api.captchas.store');
        //第三方登录
        $api->post('socials/{social_type}/authorizations','AuthorizationsController@socialStore')->name('api.socials.authorizations.store');
        // 登录
        $api->post('authorizations', 'AuthorizationsController@store')
            ->name('api.authorizations.store');
        //刷新token
        $api->put('authorizations/current','AuthorizationsController@update')->name('api.authorizations.update');
        //删除token
        $api->delete('authorizations/current', 'AuthorizationsController@destroy')->name('api.authorizations.destroy');
        //话题分类
        $api->get('categories', 'CategoriesController@index')->name('api.categories.index');
        //话题列表
        $api->get('topics','TopicsController@index')->name('api.topics.index');
        //话题详情
        $api->get('topics/{topic}','TopicsController@show')->name('api.topics.show');
        // 话题回复列表
        $api->get('topics/{topic}/replies', 'RepliesController@index')
            ->name('api.topics.replies.index');
        //某个用户的话题列表
        $api->get('users/{user}/topics', 'TopicsController@userIndex')
            ->name('api.users.topics.index');
        //某个用户的回复列表
        $api->get('users/{user}/replies','RepliesController@userIndex')->name('api.users.replies.userIndex');
        // 资源推荐
        $api->get('links', 'LinksController@index')
            ->name('api.links.index');
        // 活跃用户
        $api->get('actived/users', 'UsersController@activedIndex')
            ->name('api.actived.users.index');
        //需要token验证的接口
        $api->group(['middleware'=>'api.auth'],function ($api){
            //获取当前登录用户信息
            $api->get('user', 'UsersController@me')
                ->name('api.user.show');
            //put 替换某个资源，需提供完整的资源信息
            //patch 部分修改资源，提供部分资源信息
            //编辑登录用户信息
            $api->patch('user','UsersController@update')
                ->name('api.user.update');
            //图片资源
            $api->post('images','ImagesController@store')->name('api.images.store');
            //发布话题
            $api->post('topics', 'TopicsController@store')->name('api.topics.store');
            //修改话题
            $api->patch('topics/{topic}','TopicsController@update')->name('api.topics.update');
            $api->delete('topics/{topic}','TopicsController@destroy')->name('api.topics.destroy');
            //发布回复
            $api->post('topics/{topic}/replies', 'RepliesController@store')
                ->name('api.topics.replies.store');
            // 删除回复
            $api->delete('topics/{topic}/replies/{reply}', 'RepliesController@destroy')
                ->name('api.topics.replies.destroy');
            // 通知列表
            $api->get('user/notifications', 'NotificationsController@index')
                ->name('api.user.notifications.index');
            // 通知统计
            $api->get('user/notifications/stats', 'NotificationsController@stats')
                ->name('api.user.notifications.stats');
            // 标记消息通知为已读
            $api->patch('user/read/notifications', 'NotificationsController@read')
                ->name('api.user.notifications.read');
            //当前用户的权限
            $api->get('user/permissions','PermissionsController@index')->name('api.user.permissions.index');
        });
    });
});
$api->version('v2', function($api) {
    $api->get('version', function() {
        return response('this is version v2');
    });
});
