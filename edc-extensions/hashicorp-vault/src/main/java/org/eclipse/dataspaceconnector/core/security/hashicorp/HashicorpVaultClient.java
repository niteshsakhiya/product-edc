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
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.jetbrains.annotations.NotNull;

@RequiredArgsConstructor
class HashicorpVaultClient {
  static final String VAULT_DATA_ENTRY_NAME = "content";
  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
  private static final String VAULT_REQUEST_HEADER = "X-Vault-Request";
  private static final MediaType MEDIA_TYPE_APPLICATION_JSON = MediaType.get("application/json");
  private static final String VAULT_PATH_V1_SECRET_DATA = "/v1/secret/data";
  private static final String VAULT_PATH_V1_SECRET_METADATA = "/v1/secret/metadata";
  @NonNull private final HashicorpVaultClientConfig config;
  @NonNull private final OkHttpClient okHttpClient;
  @NonNull private final ObjectMapper objectMapper;

  @NotNull
  CompletableFuture<Result<String>> getSecretValue(@NonNull String key) {
    key = URLEncoder.encode(key, StandardCharsets.UTF_8);
    String requestURI = String.join("/", getSecretDataUrl(), key);
    Headers.Builder headersBuilder =
        new Headers.Builder().add(VAULT_REQUEST_HEADER, Boolean.toString(true));
    if (config.getVaultToken() != null) {
      headersBuilder = headersBuilder.add(VAULT_TOKEN_HEADER, config.getVaultToken());
    }
    Headers headers = headersBuilder.build();
    Request request = new Request.Builder().url(requestURI).headers(headers).get().build();

    CompletableFuture<Result<String>> completableFuture = new CompletableFuture<>();
    okHttpClient
        .newCall(request)
        .enqueue(
            new ResponseCallbackGetSecret(completableFuture, objectMapper, VAULT_DATA_ENTRY_NAME));
    return completableFuture;
  }

  CompletableFuture<Result<HashicorpVaultCreateEntryResponsePayload>> setSecret(
      @NonNull String key, @NonNull String value) {
    key = URLEncoder.encode(key, StandardCharsets.UTF_8);
    String requestURI = String.join("/", getSecretDataUrl(), key);
    Headers.Builder headersBuilder =
        new Headers.Builder().add(VAULT_REQUEST_HEADER, Boolean.toString(true));
    if (config.getVaultToken() != null) {
      headersBuilder = headersBuilder.add(VAULT_TOKEN_HEADER, config.getVaultToken());
    }
    Headers headers = headersBuilder.build();
    HashicorpVaultCreateEntryRequestPayload requestPayload =
        HashicorpVaultCreateEntryRequestPayload.builder()
            .data(Collections.singletonMap(VAULT_DATA_ENTRY_NAME, value))
            .build();
    Request request =
        new Request.Builder()
            .url(requestURI)
            .headers(headers)
            .post(createRequestBody(requestPayload))
            .build();

    CompletableFuture<Result<HashicorpVaultCreateEntryResponsePayload>> completableFuture =
        new CompletableFuture<>();
    okHttpClient
        .newCall(request)
        .enqueue(new ResponseCallbackStoreSecret(completableFuture, objectMapper));

    return completableFuture;
  }

  CompletableFuture<Result<Void>> destroySecret(@NonNull String key) {
    key = URLEncoder.encode(key, StandardCharsets.UTF_8);
    String requestURI = String.join("/", getSecretMetadataUrl(), key);
    Headers.Builder headersBuilder =
        new Headers.Builder().add(VAULT_REQUEST_HEADER, Boolean.toString(true));
    if (config.getVaultToken() != null) {
      headersBuilder = headersBuilder.add(VAULT_TOKEN_HEADER, config.getVaultToken());
    }
    Headers headers = headersBuilder.build();
    Request request = new Request.Builder().url(requestURI).headers(headers).delete().build();

    CompletableFuture<Result<Void>> completableFuture = new CompletableFuture<>();
    okHttpClient.newCall(request).enqueue(new ResponseCallbackDestroySecret(completableFuture));
    return completableFuture;
  }

  private String getBaseUrl() {
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

  private RequestBody createRequestBody(Object requestPayload) {
    String jsonRepresentation;
    try {
      jsonRepresentation = objectMapper.writeValueAsString(requestPayload);
    } catch (JsonProcessingException e) {
      throw new HashicorpVaultException(e.getMessage(), e);
    }
    return RequestBody.create(jsonRepresentation, MEDIA_TYPE_APPLICATION_JSON);
  }
}
