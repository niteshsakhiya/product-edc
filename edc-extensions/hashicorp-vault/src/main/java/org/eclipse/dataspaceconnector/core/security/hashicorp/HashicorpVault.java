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
 *       Mercedes-Benz Tech Innovation GmbH - Initial API and Implementation
 *
 */

package org.eclipse.dataspaceconnector.core.security.hashicorp;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.eclipse.dataspaceconnector.spi.monitor.Monitor;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.jetbrains.annotations.Nullable;

/** Implements a vault backed by Hashicorp Vault. */
@RequiredArgsConstructor
public class HashicorpVault implements Vault {

  @NonNull private final HashicorpVaultClient hashicorpVaultClient;
  @NonNull private final Monitor monitor;

  @Override
  public @Nullable String resolveSecret(@NonNull String key) {
    CompletableFuture<Result<String>> future = hashicorpVaultClient.getSecretValue(key);

    Result<String> result;
    try {
      result = future.get(30, TimeUnit.SECONDS);
    } catch (InterruptedException | ExecutionException | TimeoutException e) {
      throw new HashicorpVaultException(e.getMessage(), e);
    }

    if (result.failed()) {
      throw new HashicorpVaultException(
          String.join(System.lineSeparator(), result.getFailure().getMessages()));
    }
    return result.getContent();
  }

  @Override
  public Result<Void> storeSecret(String key, String value) {
    return null;
  }

  @Override
  public Result<Void> deleteSecret(String key) {
    return null;
  }
}
