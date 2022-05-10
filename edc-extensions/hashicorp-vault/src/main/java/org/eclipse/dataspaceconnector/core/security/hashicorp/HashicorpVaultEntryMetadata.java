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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class HashicorpVaultEntryMetadata {

  @JsonDeserialize(using = DataOffsetDateTimeDeserializer.class)
  @JsonProperty("created_time")
  private OffsetDateTime createdTime;

  @JsonProperty("custom_metadata")
  private Map<String, String> customMetadata;

  @JsonDeserialize(using = DataOffsetDateTimeDeserializer.class)
  @JsonProperty("deletion_time")
  private OffsetDateTime deletionTime;

  @JsonProperty("destroyed")
  private Boolean destroyed;

  private Integer version;

  public static class DataOffsetDateTimeDeserializer extends StdDeserializer<OffsetDateTime> {
    private static final DateTimeFormatter DATE_TIME_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'hh:mm:ss.SSSSSSSSSZ");

    protected DataOffsetDateTimeDeserializer() {
      super(OffsetDateTime.class);
    }

    @Override
    public OffsetDateTime deserialize(final JsonParser p, final DeserializationContext ctxt)
        throws IOException {
      final String value = p.readValueAs(String.class);

      if (value == null || value.isEmpty()) {
        return null;
      }

      return OffsetDateTime.parse(value, DATE_TIME_FORMATTER);
    }
  }
}
