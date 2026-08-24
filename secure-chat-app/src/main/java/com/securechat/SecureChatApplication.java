package com.securechat;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class SecureChatApplication {

    public static void main(String[] args) {
        // Register Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(SecureChatApplication.class, args);
    }
}
