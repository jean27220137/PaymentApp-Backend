package irojas.demo_jwt.Auth;

import irojas.demo_jwt.User.UserRepository;
import irojas.demo_jwt.User.User;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import irojas.demo_jwt.Jwt.JwtService;
import irojas.demo_jwt.User.Role;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor

public class AuthService {
        private final UserRepository userRespository;
        private final JwtService jwtService;
        private final PasswordEncoder passwordEncoder;
        private final AuthenticationManager authenticationManager;

        public AuthResponse login(LoginRequest request) {

                authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
                User user = userRespository.findByUsername(request.getUsername()).orElseThrow();
                String jwtToken = jwtService.getToken(user);
                return AuthResponse.builder()
                                .token(jwtToken)
                                .build();
        }

        public AuthResponse register(RegisterRequest request) {
                User user = User.builder()
                                .username(request.getEmail())
                                .firstname(request.getFirstname())
                                .lastname(request.getLastname())
                                .country(request.getCountry())
                                .password(passwordEncoder.encode(request.getPassword()))
                                .role(Role.USER)
                                .build();
                userRespository.save(user);
                return AuthResponse.builder()
                                .token(jwtService.getToken(user))
                                .build();
        }

}
