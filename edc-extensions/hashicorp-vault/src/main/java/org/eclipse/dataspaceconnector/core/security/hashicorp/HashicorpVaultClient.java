package org.eclipse.dataspaceconnector.core.security.hashicorp;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import lombok.RequiredArgsConstructor;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.eclipse.dataspaceconnector.spi.EdcException;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.jetbrains.annotations.NotNull;

@RequiredArgsConstructor
class HashicorpVaultClient {
  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private final HashicorpVaultClientConfig config;
  private final OkHttpClient okHttpClient;
  private final ObjectMapper objectMapper;

  @NotNull
  public CompletableFuture<Result<String>> getSecretValue(String key) {
    Request request =
        new Request.Builder()
            .url(String.format("%s/%s", config.getSecretGetUrl(), key))
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
                      HashicorpVaultEntry vaultEntry =
                          objectMapper.readValue(body.string(), HashicorpVaultEntry.class);
                      String value = Objects.requireNonNull(vaultEntry.getInnerData()).get(key);
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
}
