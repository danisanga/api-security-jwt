package com.danisanga.api.security.jwt.repositories;

import com.danisanga.api.security.jwt.models.UserModel;

public interface UserRepository {

    /**
     * Find user by email.
     *
     * @param email email address
     * @return  User object for requesting email.
     */
    UserModel findUserByEmail(String email);
}
