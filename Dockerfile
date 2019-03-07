FROM maven:3-jdk-8 AS builder

# Copy and ompile TLS-Attacker
WORKDIR /tlsattackerconnector
COPY TLS-Attacker TLS-Attacker

WORKDIR /tlsattackerconnector/TLS-Attacker
RUN mvn install -DskipTests=true

# Copy and compile the connector
WORKDIR /tlsattackerconnector
COPY . .
RUN mvn package

# Set entrypoint so this container can be used as a command
ENTRYPOINT ["java", "-jar", "target/TLSAttackerConnector2.0.jar"]
