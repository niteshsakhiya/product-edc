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
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClient.Builder;
import okhttp3.Request;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;


public class HashicorpVaultClientTest {
    private static final String key = "key";
    private HashicorpVaultClient vaultClient;
    private OkHttpClient okHttpClient;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setup() {
        HashicorpVaultClientConfig hashicorpVaultClientConfig = HashicorpVaultClientConfig.builder()
                .vaultUrl("https://mock.url")
                .vaultToken(UUID.randomUUID().toString())
                .build();

        okHttpClient = Mockito.mock(OkHttpClient.class);
        objectMapper = new ObjectMapper();
        vaultClient = new HashicorpVaultClient(hashicorpVaultClientConfig, okHttpClient, objectMapper);
    }

    @Test
    void getSecretValue() {
        // prepare
        Call call = Mockito.mock(Call.class);
        Mockito.when(okHttpClient.newCall(Mockito.any(Request.class))).thenReturn(call);
        Mockito.doNothing().when(call.enqueue(Mockito.any(HashicorpVaultClient.GetSecretResponseCallback.class)));

        // invoke
        CompletableFuture<Result<String>> completableFuture = vaultClient.getSecretValue(key);

        // verify
        Assertions.assertNotNull(completableFuture);
    }

}
