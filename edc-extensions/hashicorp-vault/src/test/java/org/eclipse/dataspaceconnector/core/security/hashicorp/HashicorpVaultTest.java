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

import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_NAME;
import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_TOKEN;
import static org.eclipse.dataspaceconnector.core.security.hashicorp.HashicorpVaultExtension.VAULT_URL;

import java.util.HashMap;
import lombok.Getter;
import org.eclipse.dataspaceconnector.junit.launcher.EdcExtension;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.eclipse.dataspaceconnector.spi.system.Inject;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtension;
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
public class HashicorpVaultTest {
  private static final String TEST_TOKEN = "test-token";
  private static final String TEST_NAME = "testing";
  private TestExtension testExtension = new TestExtension();

  @Container @ClassRule
  public static VaultContainer vaultContainer =
      new VaultContainer<>(DockerImageName.parse("vault:1.9.6"))
          .withVaultToken(TEST_TOKEN)
          .withSecretInVault(
              "secret/" + TEST_NAME, "top_secret=password1", "db_password=dbpassword1");

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
            put(VAULT_NAME, TEST_NAME);
          }
        });
    extension.registerSystemExtension(ServiceExtension.class, testExtension);
  }

  @Test
  public void testResolveSecret() {
    Vault vault = testExtension.getVault();
    String secretValue = vault.resolveSecret("top_secret");
    Assertions.assertEquals("password1", secretValue);
  }

  private static class TestExtension implements ServiceExtension {
    @Inject @Getter private Vault vault;
  }
}
