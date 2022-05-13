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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;
import org.eclipse.dataspaceconnector.spi.EdcException;
import org.eclipse.dataspaceconnector.spi.EdcSetting;
import org.eclipse.dataspaceconnector.spi.monitor.Monitor;
import org.eclipse.dataspaceconnector.spi.security.CertificateResolver;
import org.eclipse.dataspaceconnector.spi.security.PrivateKeyResolver;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.eclipse.dataspaceconnector.spi.security.VaultPrivateKeyResolver;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtensionContext;
import org.eclipse.dataspaceconnector.spi.system.VaultExtension;

public class HashicorpVaultExtension implements VaultExtension {

  @EdcSetting public static final String VAULT_URL = "edc.vault.url";

  @EdcSetting public static final String VAULT_TOKEN = "edc.vault.token";
  @EdcSetting public static final String VAULT_CERTIFICATE = "edc.vault.certificate";
  @EdcSetting public static final String VAULT_CERTIFICATE_PRIVATEKEY = "edc.vault.certificate.key";

  @EdcSetting
  public static final String VAULT_CERTIFICATE_PRIVATEKEY_PASSWORD =
      "edc.vault.certificate.key.password";

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
    String vaultUrl = Objects.requireNonNull(context.getSetting(VAULT_URL, null));

    String vaultToken = context.getSetting(VAULT_TOKEN, null);
    String vaultCertificate = context.getSetting(VAULT_CERTIFICATE, null);
    String vaultCertificateCa = context.getSetting(VAULT_CERTIFICATE_CA, null);
    String vaultCertificatePrivateKey = context.getSetting(VAULT_CERTIFICATE_PRIVATEKEY, null);
    String vaultCertificatePrivateKeyPassword =
        context.getSetting(VAULT_CERTIFICATE_PRIVATEKEY_PASSWORD, null);

    if (vaultToken != null && vaultCertificate != null) {
      throw new EdcException(
          String.format(
              "For Vault authentication either [%s] or [%s, %s] is required",
              VAULT_TOKEN, VAULT_CERTIFICATE, VAULT_CERTIFICATE_PRIVATEKEY));
    }

    X509Certificate cert = null;
    if (vaultCertificate != null) {
      cert = loadCertificate(vaultCertificate);
    }
    X509Certificate caCert = null;
    if (vaultCertificateCa != null) {
      caCert = loadCertificate(vaultCertificateCa);
    }
    PrivateKey privateKey = null;
    if (vaultCertificatePrivateKey != null) {
      privateKey = loadPrivateKey(vaultCertificatePrivateKey, vaultCertificatePrivateKeyPassword);
    }
    String vaultTimeoutString = context.getSetting(VAULT_TIMEOUT_SECONDS, "30");
    int vaultTimeoutInteger = Math.max(0, Integer.parseInt(vaultTimeoutString));
    Duration vaultTimeoutDuration = Duration.ofSeconds(vaultTimeoutInteger);

    HashicorpVaultClientConfig config =
        HashicorpVaultClientConfig.builder()
            .vaultUrl(vaultUrl)
            .vaultToken(vaultToken)
            .certificate(cert)
            .certificateCa(caCert)
            .certificatePrivateKey(privateKey)
            .timeout(vaultTimeoutDuration)
            .build();

    HashicorpVaultClient client =
        new HashicorpVaultClient(config, context.getTypeManager().getMapper());
    vault = new HashicorpVault(client, context.getMonitor(), vaultTimeoutDuration);
    certificateResolver = new HashicorpCertificateResolver(vault, context.getMonitor());
    privateKeyResolver = new VaultPrivateKeyResolver(vault);

    context.getMonitor().info("HashicorpVaultExtension: authentication/initialization complete.");
  }

  private X509Certificate loadCertificate(String representation) {
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
      throw new EdcException(exception.getMessage(), exception);
    }
  }

  private PrivateKey loadPrivateKey(String representation, String password) {
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
      throw new EdcException(exception.getMessage(), exception);
    }
  }
}
