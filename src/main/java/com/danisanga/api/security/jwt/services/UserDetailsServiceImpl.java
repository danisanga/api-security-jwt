package com.danisanga.api.security.jwt.services;

import com.danisanga.api.security.jwt.models.UserModel;
import com.danisanga.api.security.jwt.repositories.UserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        final UserModel userModel = userRepository.findUserByEmail(email);
        final List<String> roles = getRoles();
        return User.builder()
                .username(userModel.getEmail())
                .password(userModel.getPassword())
                .roles(roles.toArray(new String[0]))
                .build();
    }

    private List<String> getRoles() {
        return List.of("USER");
    }
}
