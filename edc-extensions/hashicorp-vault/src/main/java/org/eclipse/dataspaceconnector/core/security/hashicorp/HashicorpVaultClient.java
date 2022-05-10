package org.eclipse.dataspaceconnector.core.security.hashicorp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.HashMap;
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

  public String getSecretDataUrl() {
    return String.format("%s%s", config.getVaultUrl(), VAULT_SECRET_DATA_PATH);
  }

  public String getSecretMetadataUrl() {
    return String.format("%s%s", config.getVaultUrl(), VAULT_SECRET_METADATA_PATH);
  }

  @NotNull
  public CompletableFuture<Result<String>> getSecretValue(String key) {
    Request request =
        new Request.Builder()
            .url(String.format("%s%s", getSecretDataUrl(), key))
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

  public CompletableFuture<Result<CreateHashicorpVaultEntryResponsePayload>> setSecret(
      String key, String value) {
    CreateHashicorpVaultEntryRequestPayload payload =
        CreateHashicorpVaultEntryRequestPayload.builder()
            .data(
                new HashMap<String, String>() {
                  {
                    put(SECRET_KEY, value);
                  }
                })
            .build();
    String body;
    try {
      body = objectMapper.writeValueAsString(payload);
    } catch (JsonProcessingException e) {
      throw new HashicorpVaultException(e.getMessage(), e);
    }

    Request request =
        new Request.Builder()
            .url(String.format("%s%s", getSecretDataUrl(), key))
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
              public void onResponse(@NotNull Call call, @NotNull Response response)
                  throws IOException {
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

  public CompletableFuture<Result<Void>> destroySecret(String key) {
    Request request =
        new Request.Builder()
            .url(String.format("%s%s", getSecretMetadataUrl(), key))
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
