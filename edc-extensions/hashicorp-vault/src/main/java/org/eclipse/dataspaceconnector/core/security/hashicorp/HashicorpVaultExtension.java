/*
 *  Copyright (c) 2022 Mercedes-Benz Tech Innovation GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Mercedes-Benz Tech Innovation GmbH - Initial API and Implementation
 *
 */

package org.eclipse.dataspaceconnector.core.security.hashicorp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.UUID;

import lombok.NonNull;
import okhttp3.OkHttpClient;
import org.eclipse.dataspaceconnector.spi.EdcException;
import org.eclipse.dataspaceconnector.spi.EdcSetting;
import org.eclipse.dataspaceconnector.spi.monitor.Monitor;
import org.eclipse.dataspaceconnector.spi.security.CertificateResolver;
import org.eclipse.dataspaceconnector.spi.security.PrivateKeyResolver;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.eclipse.dataspaceconnector.spi.security.VaultPrivateKeyResolver;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtensionContext;
import org.eclipse.dataspaceconnector.spi.system.VaultExtension;
import org.jetbrains.annotations.Nullable;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class HashicorpVaultExtension implements VaultExtension {

  @EdcSetting(required = true) public static final String VAULT_URL = "edc.vault.url";
  @EdcSetting public static final String VAULT_TOKEN = "edc.vault.token";
  @EdcSetting public static final String VAULT_CERTIFICATE = "edc.vault.certificate";
  @EdcSetting public static final String VAULT_CERTIFICATE_PRIVATEKEY = "edc.vault.certificate.key";
  @EdcSetting public static final String VAULT_CERTIFICATE_PRIVATEKEY_PASSWORD = "edc.vault.certificate.key.password";
  @EdcSetting public static final String VAULT_CERTIFICATE_CA = "edc.vault.certificate.ca";
  @EdcSetting private static final String VAULT_TIMEOUT_SECONDS = "edc.vault.timeout.seconds";

  private Vault vault;
  private CertificateResolver certificateResolver;
  private PrivateKeyResolver privateKeyResolver;

  @Override
  public String name() {
    return "Hashicorp Vault";
  }

  @Override
  public void initialize(Monitor monitor) {
    monitor.debug("HashicorpVaultExtension: general initialization complete");
  }

  @Override
  public Vault getVault() {
    return vault;
  }

  @Override
  public PrivateKeyResolver getPrivateKeyResolver() {
    return privateKeyResolver;
  }

  @Override
  public CertificateResolver getCertificateResolver() {
    return certificateResolver;
  }

  @Override
  public void initializeVault(ServiceExtensionContext context) {
    HashicorpVaultClientConfig config = loadHashicorpVaultClientConfig(context);

    OkHttpClient okHttpClient = createOkHttpClient(config);
    HashicorpVaultClient client =
        new HashicorpVaultClient(config, okHttpClient, context.getTypeManager().getMapper());

    vault = new HashicorpVault(client, context.getMonitor(), config.getTimeout());
    certificateResolver = new HashicorpCertificateResolver(vault, context.getMonitor());
    privateKeyResolver = new VaultPrivateKeyResolver(vault);

    context.getMonitor().info("HashicorpVaultExtension: authentication/initialization complete.");
  }

  private OkHttpClient createOkHttpClient(HashicorpVaultClientConfig config) {
    X509TrustManager trustManager = null;
    if (config.getCertificateCa() != null) {
      trustManager = buildTrustManager(config.getCertificateCa());
    }

    SSLContext sslContext = null;
    if (config.getCertificate() != null && config.getCertificatePrivateKey() != null) {
      sslContext =
              buildSslContext(config.getCertificate(), config.getCertificatePrivateKey(), trustManager);
    }

    OkHttpClient.Builder builder =
            new OkHttpClient.Builder()
                    .callTimeout(config.getTimeout())
                    .readTimeout(config.getTimeout());

    if (sslContext != null) {
      assert trustManager != null;
      builder = builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
    }

    return builder.build();
  }

  private static X509TrustManager buildTrustManager(@NonNull X509Certificate caCert) {
    try {
      final TrustManagerFactory trustManagerFactory =
              TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null);
      keyStore.setCertificateEntry("caCert", caCert);
      trustManagerFactory.init(keyStore);
      return (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
    } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
      throw new HashicorpVaultException(e.getMessage(), e);
    }
  }

  private static SSLContext buildSslContext(
          @NonNull X509Certificate cert, @NonNull PrivateKey privateKey, TrustManager trustManager) {
    try {
      TrustManager[] trustManagers = null;
      if (trustManager != null) {
        trustManagers = new TrustManager[] {trustManager};
      }
      final KeyManagerFactory keyManagerFactory =
              KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, "password".toCharArray());
      keyStore.setCertificateEntry("clientCert", cert);
      String pass = UUID.randomUUID().toString();
      keyStore.setKeyEntry("key", privateKey, pass.toCharArray(), new Certificate[] {cert});
      keyManagerFactory.init(keyStore, pass.toCharArray());
      KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

      final SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(keyManagers, trustManagers, null);
      return sslContext;
    } catch (CertificateException
            | IOException
            | NoSuchAlgorithmException
            | KeyStoreException
            | KeyManagementException
            | UnrecoverableKeyException e) {
      throw new HashicorpVaultException(e.getMessage(), e);
    }
  }

  private HashicorpVaultClientConfig loadHashicorpVaultClientConfig(
      ServiceExtensionContext context) {

    String vaultUrl = context.getSetting(VAULT_URL, null);
    if (vaultUrl == null) {
      throw new HashicorpVaultException(String.format("Vault URL (%s) must be defined", VAULT_URL));
    }

    String vaultTimeoutString = context.getSetting(VAULT_TIMEOUT_SECONDS, "30");
    Duration vaultTimeoutDuration;
    try {
      int vaultTimeoutInteger = Math.max(0, Integer.parseInt(vaultTimeoutString));
      vaultTimeoutDuration = Duration.ofSeconds(vaultTimeoutInteger);
    } catch (NumberFormatException numberFormatException) {
      throw new HashicorpVaultException(
          String.format("Vault Timeout (%s) must be Integer", VAULT_TIMEOUT_SECONDS));
    }

    String vaultToken = context.getSetting(VAULT_TOKEN, null);
    String vaultCertificate = context.getSetting(VAULT_CERTIFICATE, null);
    String vaultCertificateCa = context.getSetting(VAULT_CERTIFICATE_CA, null);
    String vaultCertificatePrivateKey = context.getSetting(VAULT_CERTIFICATE_PRIVATEKEY, null);
    String vaultCertificatePrivateKeyPassword =
        context.getSetting(VAULT_CERTIFICATE_PRIVATEKEY_PASSWORD, null);

    if (vaultToken == null && (vaultCertificate == null || vaultCertificatePrivateKey == null)) {
      throw new EdcException(
          String.format(
              "For Vault authentication either [%s] or [%s, %s] are required",
              VAULT_TOKEN, VAULT_CERTIFICATE, VAULT_CERTIFICATE_PRIVATEKEY));
    }

    X509Certificate x509Certificate = null;
    if (vaultCertificate != null) {
      x509Certificate = loadCertificate(vaultCertificate);
      if (x509Certificate == null) {
        throw new HashicorpVaultException(
            String.format(
                "Vault client X509Certificate (%s) was not resolvable", VAULT_CERTIFICATE));
      }
    }
    X509Certificate caX509Certificate = null;
    if (vaultCertificateCa != null) {
      caX509Certificate = loadCertificate(vaultCertificateCa);
      if (caX509Certificate == null) {
        throw new HashicorpVaultException(
            String.format(
                "Vault CA X509Certificate (%s) was not resolvable", VAULT_CERTIFICATE_CA));
      }
    }

    PrivateKey privateKey = null;
    if (vaultCertificatePrivateKey != null) {
      privateKey = loadPrivateKey(vaultCertificatePrivateKey, vaultCertificatePrivateKeyPassword);
      if (privateKey == null) {
        throw new HashicorpVaultException(
            String.format(
                "Vault client private-key (%s) was not resolvable", VAULT_CERTIFICATE_PRIVATEKEY));
      }
    }

    return HashicorpVaultClientConfig.builder()
        .vaultUrl(vaultUrl)
        .vaultToken(vaultToken)
        .certificate(x509Certificate)
        .certificateCa(caX509Certificate)
        .certificatePrivateKey(privateKey)
        .timeout(vaultTimeoutDuration)
        .build();
  }

  private X509Certificate loadCertificate(@NonNull String representation) {
    try {
      Path path = Paths.get(representation);
      if (Files.exists(path)) {
        try (InputStream inputStream = Files.newInputStream(path)) {
          return PemUtil.readX509Certificate(inputStream);
        }
      }

      try (InputStream inputStream =
          new ByteArrayInputStream(representation.getBytes(StandardCharsets.UTF_8))) {
        return PemUtil.readX509Certificate(inputStream);
      }
    } catch (Exception exception) {
      throw new HashicorpVaultException(exception.getMessage(), exception);
    }
  }

  private PrivateKey loadPrivateKey(@NonNull String representation, @Nullable String password) {
    try {
      Path path = Paths.get(representation);
      if (Files.exists(path)) {
        try (InputStream inputStream = Files.newInputStream(path)) {
          return PemUtil.readPrivateKey(inputStream, password);
        }
      }

      try (InputStream inputStream =
          new ByteArrayInputStream(representation.getBytes(StandardCharsets.UTF_8))) {
        return PemUtil.readPrivateKey(inputStream, password);
      }
    } catch (Exception exception) {
      throw new HashicorpVaultException(exception.getMessage(), exception);
    }
  }
}
