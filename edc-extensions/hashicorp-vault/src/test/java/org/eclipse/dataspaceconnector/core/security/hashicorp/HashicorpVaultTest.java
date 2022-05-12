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

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import lombok.SneakyThrows;
import org.eclipse.dataspaceconnector.spi.monitor.Monitor;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class HashicorpVaultTest {
  private static final String key = "key";

  // mocks
  private HashicorpVaultClient vaultClient;
  private HashicorpVault vault;

  @BeforeEach
  void setup() {
    vaultClient = Mockito.mock(HashicorpVaultClient.class);
    final Monitor monitor = Mockito.mock(Monitor.class);
    vault = new HashicorpVault(vaultClient, monitor, Duration.ofSeconds(0));
  }

  @Test
  @SneakyThrows
  void getSecret() {
    // prepare
    String value = UUID.randomUUID().toString();
    CompletableFuture<Result<String>> future = Mockito.mock(CompletableFuture.class);
    Result<String> result = Mockito.mock(Result.class);
    Mockito.when(vaultClient.getSecretValue(key)).thenReturn(future);
    Mockito.when(future.get()).thenReturn(result);
    Mockito.when(result.getContent()).thenReturn(value);

    // invoke
    String returnValue = vault.resolveSecret(key);

    // verify
    Mockito.verify(vaultClient, Mockito.times(1)).getSecretValue(key);
    Assertions.assertEquals(value, returnValue);
  }
}
