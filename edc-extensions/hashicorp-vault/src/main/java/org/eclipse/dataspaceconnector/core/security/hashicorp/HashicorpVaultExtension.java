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

import java.time.Duration;
import java.util.Objects;
import okhttp3.OkHttpClient;
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

  @EdcSetting private static final String VAULT_TIMEOUT_SECONDS = "edc.vault.timeout.seconds";

  private Vault vault;

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
    return new VaultPrivateKeyResolver(vault);
  }

  @Override
  public CertificateResolver getCertificateResolver() {
    return new HashicorpCertificateResolver(vault);
  }

  @Override
  public void initializeVault(ServiceExtensionContext context) {
    String vaultUrl = Objects.requireNonNull(context.getSetting(VAULT_URL, null));
    String vaultToken = Objects.requireNonNull(context.getSetting(VAULT_TOKEN, null));
    String vaultTimeoutString = context.getSetting(VAULT_TIMEOUT_SECONDS, "30");
    int vaultTimeoutInteger = Math.max(0, Integer.parseInt(vaultTimeoutString));
    Duration vaultTimeoutDuration = Duration.ofSeconds(vaultTimeoutInteger);

    OkHttpClient httpClient =
        new OkHttpClient.Builder()
            .callTimeout(vaultTimeoutDuration)
            .readTimeout(vaultTimeoutDuration)
            .build();

    HashicorpVaultClientConfig config =
        HashicorpVaultClientConfig.builder().vaultUrl(vaultUrl).vaultToken(vaultToken).build();
    HashicorpVaultClient client =
        new HashicorpVaultClient(config, httpClient, context.getTypeManager().getMapper());
    vault = new HashicorpVault(client, context.getMonitor(), vaultTimeoutDuration);

    context.getMonitor().info("HashicorpVaultExtension: authentication/initialization complete.");
  }
}
