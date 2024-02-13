package com.danisanga.api.security.jwt.repositories.impl;

import com.danisanga.api.security.jwt.models.UserModel;
import com.danisanga.api.security.jwt.repositories.UserRepository;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepositoryImpl implements UserRepository {

    /**
     * {@inheritDoc}
     */
    public UserModel findUserByEmail(String email) {
        return new UserModel(email,"123456");
    }
}
