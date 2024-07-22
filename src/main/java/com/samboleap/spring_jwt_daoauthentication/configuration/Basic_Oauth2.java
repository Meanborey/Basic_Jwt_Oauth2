package com.samboleap.spring_jwt_daoauthentication.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class Basic_Oauth2 {
//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());
//        http.exceptionHandling(exceptions -> exceptions
//                .defaultAuthenticationEntryPointFor(
//                        new LoginUrlAuthenticationEntryPoint("/login"),
//                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//                ));
//        return http.build();
//    }
//
//    @Bean
//    @Order(2)
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf().disable().authorizeRequests()
//                .antMatchers("/h2-console/**")
//                .permitAll()
//                .anyRequest()
//                .authenticated()
//                .and().headers().frameOptions().sameOrigin()//allow use of frame to same origin urls used for h2
//                .and()
//                .httpBasic().and()
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////                .authenticationEntryPoint(authenticationEntryPoint);
////        http.addFilterAfter(new CustomFilter(), BasicAuthenticationFilter.class);
//        return http.build();
//    }
//
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId(securityComponent.getUsername())
//                .clientSecret(passwordEncoder().encode(securityComponent.getPassword()))
//                .scope(OidcScopes.OPENID)
//                .clientAuthenticationMethods(methods -> {
//                    methods.add(ClientAuthenticationMethod.NONE);
//                    methods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
//                })
////                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .authorizationGrantTypes(grantTypes -> {
//                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
//                    grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
//                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
//                })
////                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://localhost:9055/login/oauth2/code/kangchi")
//                .build();
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//
//    @Bean
//    OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
//
////        System.out.println("KANGCHI => Start Generate Token");
//
//        NimbusJwtEncoder jwtEncoder = null;
//        try {
//            jwtEncoder = new NimbusJwtEncoder(jwkSource());
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
//        jwtGenerator.setJwtCustomizer(tokenCustomizer());
//        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
//        return new DelegatingOAuth2TokenGenerator(
//                jwtGenerator, accessTokenGenerator, refreshTokenGenerator
//        );
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }
//
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
//
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//
//        var keys = keyPairGenerator.generateKeyPair();
//        var publicKey = (RSAPublicKey) keys.getPublic();
//        var privateKey = keys.getPrivate();
//
//        var rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//
//        JWKSet jwkSet = new JWKSet(rsaKey);
//
//        return new ImmutableJWKSet<>(jwkSet);
//    }
//
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }
//
//    @Bean
//    public OAuth2AuthorizationService authorizationService() {
//        return new InMemoryOAuth2AuthorizationService();
//    }
//
//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
//        return new OAuth2TokenCustomizer<JwtEncodingContext>() {
//            @Override
//            public void customize(JwtEncodingContext context) {
//
//                // TODO: Custom JWT with authorization_code grant type and Authentication
//                Authentication authentication = context.getPrincipal();
//                if (context.getTokenType().getValue().equals("id_token")) {
//                    context.getClaims().claim("skyvva", "Skyvva company");
//                }
//
//                if (context.getTokenType().getValue().equals("access_token")) {
//                    context.getClaims().claim("skyvva", "Access Token");
//                    Set<String> authorities = authentication.getAuthorities().stream()
//                            .map(GrantedAuthority::getAuthority)
//                            .collect(Collectors.toSet());
//                    context.getClaims().claim("authorities", authorities)
//                            .claim("user", authentication.getName());
//                    context.getClaims().expiresAt(Instant.now().plus(1, ChronoUnit.HOURS));
//                }
//
//            }
//        };
//    }


//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .antMatchers("/public").permitAll()
//                        .anyRequest().authenticated()
//                ).oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
////                .formLogin(Customizer.withDefaults());
////        http.csrf().disable();
//        return http.build();
//    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
//        userDetailsManager.createUser(User.withUsername("admin")
////                .password("{bcrypt}$2a$12$HuORrYYsC0M3.XtOefeuYO7iN/foUpSQTDRtKvKcKt/ylzZLiYFn6")
//                .password(passwordEncoder().encode("12345"))
//                .authorities("read", "write")
//                .build());
//        return userDetailsManager;
//    }


    /**
     * for dependency
     */
//     <dependency>
//            <groupId>org.springframework.security</groupId>
//            <artifactId>spring-security-config</artifactId>
//        </dependency>
//        <dependency>
//            <groupId>org.springframework.security</groupId>
//            <artifactId>spring-security-oauth2-authorization-server</artifactId>
//            <version>0.4.1</version> <!-- Ensure this version is compatible -->
//        </dependency>
//        <dependency>
//            <groupId>org.springframework.boot</groupId>
//            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
//        </dependency>
//        <dependency>
//            <groupId>org.springframework.boot</groupId>
//            <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
//            <version>3.2.0</version>
//        </dependency>
//        <dependency>
//            <groupId>org.springframework.security</groupId>
//            <artifactId>spring-security-oauth2-jose</artifactId>
//        </dependency>
}
