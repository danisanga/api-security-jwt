package com.danisanga.api.security.jwt.repositories;

import com.danisanga.api.security.jwt.models.User;

public interface UserRepository {

    User findUserByEmail(String email);
}
