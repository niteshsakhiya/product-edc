package org.eclipse.dataspaceconnector.core.security.hashicorp;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import okhttp3.Call;
import okhttp3.Callback;
import org.jetbrains.annotations.NotNull;

@RequiredArgsConstructor
abstract class OkHttpResponseCallback<T> implements Callback {
  @NonNull protected final CompletableFuture<T> completableFuture;

  public void onFailure(@NotNull Call call, @NotNull IOException ioException) {
    completableFuture.completeExceptionally(
        new HashicorpVaultException(ioException.getMessage(), ioException));
  }
}
