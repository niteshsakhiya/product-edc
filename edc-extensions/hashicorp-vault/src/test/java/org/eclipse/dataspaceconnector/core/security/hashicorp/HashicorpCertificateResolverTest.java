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
 *       Mercedes-Benz Tech Innovation GmbH - Initial Test
 *
 */

package org.eclipse.dataspaceconnector.core.security.hashicorp;

import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_TOKEN;
import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_URL;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.UUID;
import lombok.Getter;
import lombok.SneakyThrows;
import org.eclipse.dataspaceconnector.junit.launcher.EdcExtension;
import org.eclipse.dataspaceconnector.spi.security.CertificateResolver;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtension;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtensionContext;
import org.junit.ClassRule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

@Testcontainers
@ExtendWith(EdcExtension.class)
public class HashicorpCertificateResolverTest {
  private static final String DOCKER_IMAGE_NAME = "vault:1.9.6";
  private static final String TEST_TOKEN = "test-token";

  private final TestExtension testExtension = new TestExtension();

  @Container @ClassRule
  public static final VaultContainer<?> vaultContainer =
      new VaultContainer<>(DockerImageName.parse(DOCKER_IMAGE_NAME)).withVaultToken(TEST_TOKEN);

  @BeforeEach
  void beforeEach(EdcExtension extension) {
    extension.setConfiguration(
        new HashMap<>() {
          {
            put(
                VAULT_URL,
                String.format(
                    "http://%s:%s", vaultContainer.getHost(), vaultContainer.getFirstMappedPort()));
            put(VAULT_TOKEN, TEST_TOKEN);
          }
        });
    extension.registerSystemExtension(ServiceExtension.class, testExtension);
  }

  @Test
  @SneakyThrows
  void resolveCertificate_success() {
    String key = UUID.randomUUID().toString();
    X509TestCertificateGenerator testCertificateGenerator = new X509TestCertificateGenerator();
    X509Certificate certificateExpected = testCertificateGenerator.generateCertificate(5, "Test");
    String pem = testCertificateGenerator.convertToPem(certificateExpected);

    Vault vault = testExtension.getVault();
    vault.storeSecret(key, pem);
    CertificateResolver resolver = testExtension.getCertificateResolver();
    X509Certificate certificateResult = resolver.resolveCertificate(key);

    Assertions.assertEquals(certificateExpected, certificateResult);
  }

  @Test
  @SneakyThrows
  void resolveCertificate_malformed() {
    String key = UUID.randomUUID().toString();
    String value = UUID.randomUUID().toString();
    Vault vault = testExtension.getVault();
    vault.storeSecret(key, value);

    CertificateResolver resolver = testExtension.getCertificateResolver();
    X509Certificate certificateResult = resolver.resolveCertificate(key);
    Assertions.assertNull(certificateResult);
  }

  @Getter
  private static class TestExtension implements ServiceExtension {
    private Vault vault;
    private CertificateResolver certificateResolver;

    @Override
    public void initialize(ServiceExtensionContext context) {
      vault = context.getService(Vault.class);
      certificateResolver = context.getService(CertificateResolver.class);
    }
  }
}
