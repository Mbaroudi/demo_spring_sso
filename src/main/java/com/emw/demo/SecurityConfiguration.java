/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.emw.demo;

import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.KeyStore;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	 	@Value("${myapp.keystore.password}")
	    private String keystorePassword;

	    @Value("${myapp.keystore.alias}")
	    private String keystoreAlias;
	    
	    @Value("${myapp.keystore.alias-password}")
	    private String keyAliasPassword;


	    @Bean
	    KeyManagerFactory keyManagerFactory() throws Exception {
	        KeyStore keystore = KeyStore.getInstance("JKS");
	        // make sure your keystore file is correctly placed and accessible
	        FileInputStream inputStream = new FileInputStream("/Users/malek/Downloads/demoMAVEN/src/main/resources/credentials/my-keystore.jks");
	        // make sure keystorePassword contains the correct password for your keystore
	        keystore.load(inputStream, keystorePassword.toCharArray());
	        inputStream.close();

	        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	        // make sure keyAliasPassword contains the correct password for your key alias
	        keyManagerFactory.init(keystore, keyAliasPassword.toCharArray());

	        return keyManagerFactory;
	    }


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) throws Exception {
        RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(
                relyingPartyRegistrationRepository);
        Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(relyingPartyRegistrationResolver,
                new OpenSamlMetadataResolver());
        // @formatter:off
        http
            .authorizeHttpRequests((authorize) -> authorize
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated()
            )
            .saml2Login(Customizer.withDefaults())
            .saml2Logout(Customizer.withDefaults())
            .addFilterBefore(metadataFilter, Saml2WebSsoAuthenticationFilter.class);
        // @formatter:on
        return http.build();
    }

}