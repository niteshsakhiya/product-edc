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

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class HashicorpVaultClientTest {
  private static final String key = "key";
  private static final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void getSecretValue() {
    // prepare
    String vaultUrl = "https://mock.url";
    String vaultToken = UUID.randomUUID().toString();
    HashicorpVaultClientConfig hashicorpVaultClientConfig =
        HashicorpVaultClientConfig.builder().vaultUrl(vaultUrl).vaultToken(vaultToken).build();

    OkHttpClient okHttpClient = Mockito.mock(OkHttpClient.class);
    HashicorpVaultClient vaultClient =
        new HashicorpVaultClient(hashicorpVaultClientConfig, okHttpClient, objectMapper);

    Call call = Mockito.mock(Call.class);
    Mockito.when(okHttpClient.newCall(Mockito.any(Request.class))).thenReturn(call);
    Mockito.doNothing().when(call).enqueue(Mockito.any(ResponseCallbackGetSecret.class));

    // invoke
    CompletableFuture<Result<String>> completableFuture = vaultClient.getSecretValue(key);

    // verify
    Assertions.assertNotNull(completableFuture);
    Mockito.verify(okHttpClient, Mockito.times(1))
        .newCall(
            Mockito.argThat(
                request ->
                    request.method().equalsIgnoreCase("GET")
                        && request.url().encodedPath().contains("/v1/secret/data")
                        && request.url().encodedPathSegments().contains(key)));
  }

  @Test
  void setSecretValue() {
    // prepare
    String vaultUrl = "https://mock.url";
    String vaultToken = UUID.randomUUID().toString();
    String secretValue = UUID.randomUUID().toString();
    HashicorpVaultClientConfig hashicorpVaultClientConfig =
        HashicorpVaultClientConfig.builder().vaultUrl(vaultUrl).vaultToken(vaultToken).build();

    OkHttpClient okHttpClient = Mockito.mock(OkHttpClient.class);
    HashicorpVaultClient vaultClient =
        new HashicorpVaultClient(hashicorpVaultClientConfig, okHttpClient, objectMapper);

    Call call = Mockito.mock(Call.class);
    Mockito.when(okHttpClient.newCall(Mockito.any(Request.class))).thenReturn(call);
    Mockito.doNothing().when(call).enqueue(Mockito.any(ResponseCallbackStoreSecret.class));

    // invoke
    CompletableFuture<Result<HashicorpVaultCreateEntryResponsePayload>> completableFuture =
        vaultClient.setSecret(key, secretValue);

    // verify
    Assertions.assertNotNull(completableFuture);
    Mockito.verify(okHttpClient, Mockito.times(1))
        .newCall(
            Mockito.argThat(
                request ->
                    request.method().equalsIgnoreCase("POST")
                        && request.url().encodedPath().contains("/v1/secret/data")
                        && request.url().encodedPathSegments().contains(key)));
  }

  @Test
  void destroySecretValue() {
    // prepare
    String vaultUrl = "https://mock.url";
    String vaultToken = UUID.randomUUID().toString();
    HashicorpVaultClientConfig hashicorpVaultClientConfig =
        HashicorpVaultClientConfig.builder().vaultUrl(vaultUrl).vaultToken(vaultToken).build();

    OkHttpClient okHttpClient = Mockito.mock(OkHttpClient.class);
    HashicorpVaultClient vaultClient =
        new HashicorpVaultClient(hashicorpVaultClientConfig, okHttpClient, objectMapper);

    Call call = Mockito.mock(Call.class);
    Mockito.when(okHttpClient.newCall(Mockito.any(Request.class))).thenReturn(call);
    Mockito.doNothing().when(call).enqueue(Mockito.any(ResponseCallbackStoreSecret.class));

    // invoke
    CompletableFuture<Result<Void>> completableFuture = vaultClient.destroySecret(key);

    // verify
    Assertions.assertNotNull(completableFuture);
    Mockito.verify(okHttpClient, Mockito.times(1))
        .newCall(
            Mockito.argThat(
                request ->
                    request.method().equalsIgnoreCase("DELETE")
                        && request.url().encodedPath().contains("/v1/secret/metadata")
                        && request.url().encodedPathSegments().contains(key)));
  }
}
