package com.danisanga.api.security.jwt.repositories;

import com.danisanga.api.security.jwt.models.User;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepositoryImpl implements UserRepository {
    /**
     * {@inheritDoc}
     */
    public User findUserByEmail(String email) {
        return new User(email,"123456");
    }
}
