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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import lombok.RequiredArgsConstructor;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.eclipse.dataspaceconnector.spi.EdcException;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.jetbrains.annotations.NotNull;

@RequiredArgsConstructor
class HashicorpVaultClient {
  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
  static final String SECRET_KEY = "key";
  private static final String VAULT_SECRET_DATA_PATH = "/v1/secret/data/";
  private static final String VAULT_SECRET_METADATA_PATH = "/v1/secret/metadata/";

  private final HashicorpVaultClientConfig config;
  private final OkHttpClient okHttpClient;
  private final ObjectMapper objectMapper;

  private String getSecretDataUrl() {
    return String.format("%s%s", config.getVaultUrl(), VAULT_SECRET_DATA_PATH);
  }

  private String getSecretMetadataUrl() {
    return String.format("%s%s", config.getVaultUrl(), VAULT_SECRET_METADATA_PATH);
  }

  @NotNull
  CompletableFuture<Result<String>> getSecretValue(String key) {
    Request request =
        new Request.Builder()
            .url(
                String.format(
                    "%s%s", getSecretDataUrl(), URLEncoder.encode(key, StandardCharsets.UTF_8)))
            .get()
            .header(VAULT_TOKEN_HEADER, config.getVaultToken())
            .build();

    CompletableFuture<Result<String>> future = new CompletableFuture<>();
    okHttpClient
        .newCall(request)
        .enqueue(
            new Callback() {
              @Override
              public void onResponse(@NotNull Call call, @NotNull Response response) {
                if (response.code() == 404) {
                  future.complete(null);
                  return;
                }
                if (response.isSuccessful()) {
                  try (var body = response.body()) {
                    if (body == null) {
                      future.completeExceptionally(
                          new EdcException("Received an empty body response from vault"));
                    } else {
                      GetHashicorpVaultEntryResponsePayload payload =
                          objectMapper.readValue(
                              body.string(), GetHashicorpVaultEntryResponsePayload.class);
                      String value =
                          Objects.requireNonNull(payload.getData().getData().get(SECRET_KEY));
                      future.complete(Result.success(value));
                    }
                  } catch (Exception e) {
                    future.completeExceptionally(e);
                  }
                } else {
                  future.complete(
                      Result.failure(String.format("Call unsuccessful: %s", response.code())));
                }
              }

              @Override
              public void onFailure(@NotNull Call call, @NotNull IOException e) {
                future.completeExceptionally(new HashicorpVaultException(e.getMessage(), e));
              }
            });
    return future;
  }

  CompletableFuture<Result<CreateHashicorpVaultEntryResponsePayload>> setSecret(
      String key, String value) {
    Map<String, String> entries = new HashMap<>();
    entries.put(SECRET_KEY, value);
    CreateHashicorpVaultEntryRequestPayload payload =
        CreateHashicorpVaultEntryRequestPayload.builder().data(entries).build();
    String body;
    try {
      body = objectMapper.writeValueAsString(payload);
    } catch (JsonProcessingException e) {
      throw new HashicorpVaultException(e.getMessage(), e);
    }

    Request request =
        new Request.Builder()
            .url(
                String.format(
                    "%s%s", getSecretDataUrl(), URLEncoder.encode(key, StandardCharsets.UTF_8)))
            .post(RequestBody.create(body, MediaType.get("application/json")))
            .header(VAULT_TOKEN_HEADER, config.getVaultToken())
            .build();

    CompletableFuture<Result<CreateHashicorpVaultEntryResponsePayload>> future =
        new CompletableFuture<>();

    okHttpClient
        .newCall(request)
        .enqueue(
            new Callback() {
              @Override
              public void onFailure(@NotNull Call call, @NotNull IOException e) {
                future.completeExceptionally(new HashicorpVaultException(e.getMessage(), e));
              }

              @Override
              public void onResponse(@NotNull Call call, @NotNull Response response) {
                if (response.isSuccessful()) {
                  try (var body = response.body()) {
                    if (body == null) {
                      future.completeExceptionally(
                          new EdcException("Received an empty body response from vault"));
                    } else {
                      CreateHashicorpVaultEntryResponsePayload payload =
                          objectMapper.readValue(
                              body.string(), CreateHashicorpVaultEntryResponsePayload.class);

                      future.complete(Result.success(payload));
                    }
                  } catch (Exception e) {
                    future.completeExceptionally(e);
                  }
                } else {
                  future.complete(
                      Result.failure(String.format("Call unsuccessful: %s", response.code())));
                }
              }
            });
    return future;
  }

  CompletableFuture<Result<Void>> destroySecret(String key) {
    Request request =
        new Request.Builder()
            .url(
                String.format(
                    "%s%s", getSecretMetadataUrl(), URLEncoder.encode(key, StandardCharsets.UTF_8)))
            .delete()
            .header(VAULT_TOKEN_HEADER, config.getVaultToken())
            .build();

    CompletableFuture<Result<Void>> future = new CompletableFuture<>();
    okHttpClient
        .newCall(request)
        .enqueue(
            new Callback() {
              @Override
              public void onResponse(@NotNull Call call, @NotNull Response response) {
                if (response.isSuccessful() || response.code() == 404) {
                  future.complete(Result.success());
                } else {
                  future.complete(
                      Result.failure(String.format("Call unsuccessful: %s", response.code())));
                }
              }

              public void onFailure(@NotNull Call call, @NotNull IOException e) {
                future.completeExceptionally(new HashicorpVaultException(e.getMessage(), e));
              }
            });
    return future;
  }
}
