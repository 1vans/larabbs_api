<?php

namespace App\Http\Requests;

class ReplyRequest extends Request
{
    public function rules()
    {
        return [
            'contents' => 'required|min:2',
        ];
    }
}