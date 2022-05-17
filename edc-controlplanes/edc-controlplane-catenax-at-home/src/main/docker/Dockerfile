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

FROM openjdk:11-jre-slim-buster
ARG JAR
ARG LIB

ENV JAVA_TOOL_OPTIONS -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8090

WORKDIR /app

COPY ${JAR} edc-controlplane.jar
COPY ${LIB} ./lib/
ENTRYPOINT java \
    -Dedc.fs.config=/app/configuration.properties \
    -Djava.util.logging.config.file=/app/logging.properties \
    -Djava.security.edg=file:/dev/.urandom \
    -jar \
    edc-controlplane.jar
