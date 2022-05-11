/*
 *  Copyright (c) 2020, 2021 Microsoft Corporation
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

import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultClient.SECRET_KEY;
import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_TOKEN;
import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_URL;

import java.util.HashMap;
import java.util.UUID;
import lombok.Getter;
import org.eclipse.dataspaceconnector.junit.launcher.EdcExtension;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtension;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtensionContext;
import org.junit.ClassRule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

@Testcontainers
@ExtendWith(EdcExtension.class)
public class HashicorpVaultTest {
  private static final String DOCKER_IMAGE_NAME = "vault:1.9.6";
  private static final String TEST_TOKEN = "test-token";
  private static final String TEST_KEY = "testing";
  private final TestExtension testExtension = new TestExtension();
  private static final String TEST_VALUE = UUID.randomUUID().toString();

  @Container @ClassRule
  public static final VaultContainer<?> vaultContainer =
      new VaultContainer<>(DockerImageName.parse(DOCKER_IMAGE_NAME))
          .withVaultToken(TEST_TOKEN)
          .withSecretInVault("secret/" + TEST_KEY, String.format("%s=%s", SECRET_KEY, TEST_VALUE));

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
  @DisplayName("Resolve a secret that exists")
  public void testResolveSecret_exists() {
    Vault vault = testExtension.getVault();
    String secretValue = vault.resolveSecret(TEST_KEY);
    Assertions.assertEquals(TEST_VALUE, secretValue);
  }

  @Test
  @DisplayName("Resolve a secret that does not exist")
  public void testResolveSecret_doesNotExist() {
    Vault vault = testExtension.getVault();
    Assertions.assertNull(vault.resolveSecret("wrong_key"));
  }

  @Test
  @DisplayName("Update a secret that exists")
  public void testSetSecret_exists() {
    String key = UUID.randomUUID().toString();
    String value1 = UUID.randomUUID().toString();
    String value2 = UUID.randomUUID().toString();

    Vault vault = testExtension.getVault();
    vault.storeSecret(key, value1);
    vault.storeSecret(key, value2);
    String secretValue = vault.resolveSecret(key);
    Assertions.assertEquals(value2, secretValue);
  }

  @Test
  @DisplayName("Create a secret that does not exist")
  public void testSetSecret_doesNotExist() {
    String key = UUID.randomUUID().toString();
    String value = UUID.randomUUID().toString();

    Vault vault = testExtension.getVault();
    vault.storeSecret(key, value);
    String secretValue = vault.resolveSecret(key);
    Assertions.assertEquals(value, secretValue);
  }

  @Test
  @DisplayName("Delete a secret that exists")
  public void testDeleteSecret_exists() {
    String key = UUID.randomUUID().toString();
    String value = UUID.randomUUID().toString();

    Vault vault = testExtension.getVault();
    vault.storeSecret(key, value);
    vault.deleteSecret(key);

    Assertions.assertNull(vault.resolveSecret(key));
  }

  @Test
  @DisplayName("Try to delete a secret that does not exist")
  public void testDeleteSecret_doesNotExist() {
    String key = UUID.randomUUID().toString();

    Vault vault = testExtension.getVault();
    vault.deleteSecret(key);

    Assertions.assertNull(vault.resolveSecret(key));
  }

  private static class TestExtension implements ServiceExtension {
    @Getter private Vault vault;

    @Override
    public void initialize(ServiceExtensionContext context) {
      vault = context.getService(Vault.class);
    }
  }
}
