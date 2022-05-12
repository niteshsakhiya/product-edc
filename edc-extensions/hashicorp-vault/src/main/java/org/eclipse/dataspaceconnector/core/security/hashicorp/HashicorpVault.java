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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.eclipse.dataspaceconnector.spi.monitor.Monitor;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/** Implements a vault backed by Hashicorp Vault. */
@RequiredArgsConstructor
class HashicorpVault implements Vault {

  @NonNull private final HashicorpVaultClient hashicorpVaultClient;
  @NonNull private final Monitor monitor;
  @NonNull private final Duration timeoutDuration;

  @Override
  public @Nullable String resolveSecret(@NonNull String key) {
    CompletableFuture<Result<String>> future = hashicorpVaultClient.getSecretValue(key);

    Result<String> result = getResult(future);
    if (result == null) {
      return null;
    }

    if (result.failed()) {
      throw new HashicorpVaultException(
          String.join(System.lineSeparator(), result.getFailure().getMessages()));
    }
    return result.getContent();
  }

  @Override
  @NotNull
  public Result<Void> storeSecret(@NotNull @NonNull String key, @NotNull @NonNull String value) {
    CompletableFuture<Result<CreateHashicorpVaultEntryResponsePayload>> future =
        hashicorpVaultClient.setSecret(key, value);

    Result<CreateHashicorpVaultEntryResponsePayload> result = getResult(future);

    return result.succeeded() ? Result.success() : Result.failure(result.getFailureMessages());
  }

  @Override
  public Result<Void> deleteSecret(@NotNull @NonNull String key) {
    CompletableFuture<Result<Void>> future = hashicorpVaultClient.destroySecret(key);

    return getResult(future);
  }

  @SneakyThrows
  private <T> Result<T> getResult(CompletableFuture<Result<T>> future) {
    Result<T> result;
    try {
      if (timeoutDuration.isZero()) {
        result = future.get();
      } else {
        result = future.get(timeoutDuration.getSeconds(), TimeUnit.SECONDS);
      }
    } catch (ExecutionException | TimeoutException e) {
      if (e.getCause() instanceof HashicorpVaultException) {
        throw (HashicorpVaultException) e.getCause();
      }

      throw new HashicorpVaultException(e.getMessage(), e);
    }

    return result;
  }
}
