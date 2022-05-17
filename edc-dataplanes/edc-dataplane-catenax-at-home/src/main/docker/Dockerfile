#
#  Copyright (c) 2022 ZF Friedrichshafen AG
#
#  This program and the accompanying materials are made available under the
#  terms of the Apache License, Version 2.0 which is available at
#  https://www.apache.org/licenses/LICENSE-2.0
#
#  SPDX-License-Identifier: Apache-2.0
#
#  Contributors:
#       ZF Friedrichshafen AG - Initial Dockerfile
#
FROM gcr.io/distroless/java11-debian11
ARG JAR
ARG LIB

WORKDIR /app
COPY ${JAR} edc-dataplane.jar
COPY ${LIB} ./lib/

CMD ["-Dedc.fs.config=/app/configuration.properties", \
     "-Djava.util.logging.config.file=/app/logging.properties", \
     "-Djava.security.edg=file:/dev/.urandom", \
     "-jar", \
     "edc-dataplane.jar"]
