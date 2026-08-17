// Copyright 2021-present StarRocks, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.starrocks.common.util;

import com.google.common.base.Strings;
import com.starrocks.common.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public final class SSLUtil {
    private static final Logger LOG = LogManager.getLogger(SSLUtil.class);

    private SSLUtil() {
    }

    public static KeyStore loadKeyStore(String filepath, String keystorePassword, String storeType,
                                        String storeProvider, String storeName) throws Exception {
        String resolvedType = Strings.isNullOrEmpty(storeType) ? "JKS" : storeType;
        KeyStore keyStore = Strings.isNullOrEmpty(storeProvider) ? KeyStore.getInstance(resolvedType) :
                KeyStore.getInstance(resolvedType, storeProvider);
        try (InputStream keyStoreIS = new FileInputStream(filepath)) {
            keyStore.load(keyStoreIS, keystorePassword.toCharArray());
        } catch (Exception e) {
            throw new GeneralSecurityException(String.format(
                    "Failed to load SSL %s file '%s' with type '%s'%s",
                    storeName, filepath, resolvedType,
                    Strings.isNullOrEmpty(storeProvider) ? "" : " and provider '" + storeProvider + "'"), e);
        }
        return keyStore;
    }

    public static KeyManagerFactory createKeyManagerFactory() throws GeneralSecurityException {
        String algorithm = Strings.isNullOrEmpty(Config.ssl_key_manager_algorithm) ?
                KeyManagerFactory.getDefaultAlgorithm() : Config.ssl_key_manager_algorithm;
        return KeyManagerFactory.getInstance(algorithm);
    }

    public static TrustManagerFactory createTrustManagerFactory() throws GeneralSecurityException {
        String algorithm = Strings.isNullOrEmpty(Config.ssl_trust_manager_algorithm) ?
                TrustManagerFactory.getDefaultAlgorithm() : Config.ssl_trust_manager_algorithm;
        return TrustManagerFactory.getInstance(algorithm);
    }

    public static void registerSecurityProviderIfNeeded(Class<?> callerClass) throws Exception {
        if (Strings.isNullOrEmpty(Config.ssl_security_provider_class)) {
            return;
        }
        if (!Strings.isNullOrEmpty(Config.ssl_security_provider_name) &&
                Security.getProvider(Config.ssl_security_provider_name) != null) {
            return;
        }

        Class<?> providerClass;
        if (Strings.isNullOrEmpty(Config.ssl_security_provider_path)) {
            providerClass = Class.forName(Config.ssl_security_provider_class);
        } else {
            String[] paths = Config.ssl_security_provider_path.split(File.pathSeparator);
            URL[] urls = new URL[paths.length];
            for (int i = 0; i < paths.length; i++) {
                urls[i] = new File(paths[i]).toURI().toURL();
            }
            URLClassLoader classLoader = new URLClassLoader(urls, callerClass.getClassLoader());
            providerClass = Class.forName(Config.ssl_security_provider_class, true, classLoader);
        }

        Object providerObject = providerClass.getDeclaredConstructor().newInstance();
        if (!(providerObject instanceof Provider)) {
            throw new GeneralSecurityException("SSL security provider class " +
                    Config.ssl_security_provider_class + " is not a java.security.Provider");
        }
        Provider provider = (Provider) providerObject;
        if (!Strings.isNullOrEmpty(Config.ssl_security_provider_name) &&
                !Config.ssl_security_provider_name.equals(provider.getName())) {
            throw new GeneralSecurityException("Configured SSL security provider name " +
                    Config.ssl_security_provider_name + " does not match provider class name " + provider.getName());
        }
        Security.addProvider(provider);
        LOG.info("Registered SSL security provider {} from {}", provider.getName(),
                Strings.isNullOrEmpty(Config.ssl_security_provider_path) ? "classpath" :
                        Config.ssl_security_provider_path);
    }
}
