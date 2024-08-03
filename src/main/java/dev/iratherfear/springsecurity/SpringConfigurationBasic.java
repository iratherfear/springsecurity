package dev.iratherfear.springsecurity;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SpringConfigurationBasic  {
    
    @Bean
    public SecurityFilterChain applicationSecurity(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
            .httpBasic().and()
            .headers().frameOptions().sameOrigin().and()
            .build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        UserDetails user1 = User.withUsername("test1")
                                .password("test")
                                .passwordEncoder(password -> passwordEncoder().encode(password))
                                .roles("USER")
                                .build();
        
        UserDetails user2 = User.withUsername("test2")
                                .password("test")
                                .passwordEncoder(password -> passwordEncoder().encode(password))
                                .roles("ADMIN")
                                .build();

        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user1);
        jdbcUserDetailsManager.createUser(user2);

        return new InMemoryUserDetailsManager(user1, user2);
    }

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                        .setType(EmbeddedDatabaseType.H2)
                        .addScript(org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                        .build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
