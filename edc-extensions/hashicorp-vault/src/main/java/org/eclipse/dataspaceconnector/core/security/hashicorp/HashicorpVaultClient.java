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
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.jetbrains.annotations.NotNull;

@RequiredArgsConstructor
class HashicorpVaultClient {
  private static final String ERROR_TEMPLATE = "Call unsuccessful: %s";
  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
  private static final MediaType MEDIA_TYPE_APPLICATION_JSON = MediaType.get("application/json");
  private static final String VAULT_PATH_V1_SECRET_DATA = "/v1/secret/data";
  private static final String VAULT_PATH_V1_SECRET_METADATA = "/v1/secret/metadata";

  static final String VAULT_DATA_ENTRY_NAME = "content";

  private final HashicorpVaultClientConfig config;
  private final OkHttpClient okHttpClient;
  private final ObjectMapper objectMapper;

  protected String getBaseUrl() {
    String baseUrl = config.getVaultUrl();

    if (baseUrl.endsWith("/")) {
      baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
    }

    return baseUrl;
  }

  private String getSecretDataUrl() {
    return URI.create(String.join("", getBaseUrl(), VAULT_PATH_V1_SECRET_DATA)).toString();
  }

  private String getSecretMetadataUrl() {
    return URI.create(String.join("", getBaseUrl(), VAULT_PATH_V1_SECRET_METADATA)).toString();
  }

  @NotNull
  CompletableFuture<Result<String>> getSecretValue(@NonNull String key) {
    key = URLEncoder.encode(key, StandardCharsets.UTF_8);
    String requestURI = String.join("/", getSecretDataUrl(), key);
    Headers headers = new Headers.Builder().add(VAULT_TOKEN_HEADER, config.getVaultToken()).build();
    Request request = new Request.Builder().url(requestURI).headers(headers).get().build();

    CompletableFuture<Result<String>> completableFuture = new CompletableFuture<>();
    okHttpClient
        .newCall(request)
        .enqueue(
            new OkHttpResponseCallback(
                completableFuture,
                (response) -> {
                  if (response.code() == 404) {
                    completableFuture.complete(null);
                    return;
                  }

                  if (response.isSuccessful()) {
                    try (ResponseBody body = response.body()) {
                      if (body == null) {
                        completableFuture.completeExceptionally(
                            new HashicorpVaultException(
                                "Received an empty body response from vault"));

                        return;
                      }

                      GetHashicorpVaultEntryResponsePayload payload =
                          objectMapper.readValue(
                              body.string(), GetHashicorpVaultEntryResponsePayload.class);

                      String value =
                          Objects.requireNonNull(
                              payload.getData().getData().get(VAULT_DATA_ENTRY_NAME));

                      completableFuture.complete(Result.success(value));
                    } catch (Exception exception) {
                      completableFuture.completeExceptionally(exception);
                    }

                    return;
                  }

                  completableFuture.complete(
                      Result.failure(String.format(ERROR_TEMPLATE, response.code())));
                }));
    return completableFuture;
  }

  private RequestBody createRequestBody(Object requestPayload) {
    String jsonRepresentation;
    try {
      jsonRepresentation = objectMapper.writeValueAsString(requestPayload);
    } catch (JsonProcessingException e) {
      throw new HashicorpVaultException(e.getMessage(), e);
    }
    return RequestBody.create(jsonRepresentation, MEDIA_TYPE_APPLICATION_JSON);
  }

  CompletableFuture<Result<CreateHashicorpVaultEntryResponsePayload>> setSecret(
      @NonNull String key, @NonNull String value) {
    key = URLEncoder.encode(key, StandardCharsets.UTF_8);
    String requestURI = String.join("/", getSecretDataUrl(), key);
    Headers headers = new Headers.Builder().add(VAULT_TOKEN_HEADER, config.getVaultToken()).build();
    CreateHashicorpVaultEntryRequestPayload requestPayload =
        CreateHashicorpVaultEntryRequestPayload.builder()
            .data(Collections.singletonMap(VAULT_DATA_ENTRY_NAME, value))
            .build();
    Request request =
        new Request.Builder()
            .url(requestURI)
            .headers(headers)
            .post(createRequestBody(requestPayload))
            .build();

    CompletableFuture<Result<CreateHashicorpVaultEntryResponsePayload>> completableFuture =
        new CompletableFuture<>();
    okHttpClient
        .newCall(request)
        .enqueue(
            new OkHttpResponseCallback(
                completableFuture,
                (response) -> {
                  if (response.isSuccessful()) {
                    try (ResponseBody responseBody = response.body()) {
                      if (responseBody == null) {
                        completableFuture.completeExceptionally(
                            new HashicorpVaultException(
                                "Received an empty body response from vault"));

                        return;
                      }

                      CreateHashicorpVaultEntryResponsePayload responsePayload =
                          objectMapper.readValue(
                              responseBody.string(),
                              CreateHashicorpVaultEntryResponsePayload.class);

                      completableFuture.complete(Result.success(responsePayload));
                    } catch (Exception exception) {
                      completableFuture.completeExceptionally(exception);
                    }
                    return;
                  }

                  completableFuture.complete(
                      Result.failure(String.format(ERROR_TEMPLATE, response.code())));
                }));

    return completableFuture;
  }

  CompletableFuture<Result<Void>> destroySecret(@NonNull String key) {
    key = URLEncoder.encode(key, StandardCharsets.UTF_8);
    String requestURI = String.join("/", getSecretMetadataUrl(), key);
    Headers headers = new Headers.Builder().add(VAULT_TOKEN_HEADER, config.getVaultToken()).build();

    Request request = new Request.Builder().url(requestURI).headers(headers).delete().build();

    CompletableFuture<Result<Void>> completableFuture = new CompletableFuture<>();
    okHttpClient
        .newCall(request)
        .enqueue(
            new OkHttpResponseCallback(
                completableFuture,
                (response) -> {
                  if (response.isSuccessful() || response.code() == 404) {
                    completableFuture.complete(Result.success());

                    return;
                  }

                  completableFuture.complete(
                      Result.failure(String.format(ERROR_TEMPLATE, response.code())));
                }));
    return completableFuture;
  }

  @RequiredArgsConstructor
  private static class OkHttpResponseCallback implements Callback {
    @NonNull private final CompletableFuture<?> completableFuture;
    @NonNull private final Consumer<Response> responseConsumer;

    public void onFailure(@NotNull Call call, @NotNull IOException ioException) {
      completableFuture.completeExceptionally(
          new HashicorpVaultException(ioException.getMessage(), ioException));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) {
      responseConsumer.accept(response);
    }
  }
}
