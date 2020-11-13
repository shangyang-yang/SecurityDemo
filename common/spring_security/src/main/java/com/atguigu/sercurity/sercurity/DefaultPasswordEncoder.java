package com.atguigu.sercurity.sercurity;

import com.atguigu.utils.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author shangyangyang
 */
@Component
public class DefaultPasswordEncoder implements PasswordEncoder {

    public DefaultPasswordEncoder(){
        this(-1);
    }
    public DefaultPasswordEncoder(int strength){

    }

    /**
     *   进行MD5加密
     */
    @Override
    public String encode(CharSequence charSequence) {

        return MD5.encrypt(charSequence.toString());
    }

    /**
     * 进行密码的比对
     */
    @Override
    public boolean matches(CharSequence charSequence, String encodedPassword) {
        return encodedPassword.equals(MD5.encrypt(charSequence.toString()));
    }
}
