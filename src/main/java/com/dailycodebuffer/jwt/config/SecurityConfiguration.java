package com.dailycodebuffer.jwt.config;

import com.dailycodebuffer.jwt.filter.JwtFilter;
import com.dailycodebuffer.jwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        prePostEnabled = true
        //securedEnabled = true,
        //jsr250Enabled = true
)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{
    //this is the security configuration class which extends websecurity configuration

    @Autowired
    private UserService userService;
    @Autowired
    private JwtAuthenticationEntryPoint entryPoint;

    @Autowired
    private JwtFilter jwtFilter;

    @Autowired
    private CustomAccessDeniedHandler accessDeniedHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //here we are using the userdetails service
        //passing the reference of the userservice here to get the user details
        auth.userDetailsService(userService);
    }

    //this is used to authenticate the user
    //implementaion is provided by spring security core
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    //we overrride the configure methods
    //we are blocking all the routes except 'authenticate'
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/authenticate")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().authenticationEntryPoint(entryPoint)
                .accessDeniedHandler(accessDeniedHandler)
        ;
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);//adding the filter here

    }
}
