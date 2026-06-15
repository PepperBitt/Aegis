FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN apk add --no-cache maven && mvn clean package -DskipTests -q

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN addgroup -S aegis && adduser -S aegis -G aegis
COPY --from=build /app/target/*.jar app.jar
RUN mkdir -p /app/reports && chown -R aegis:aegis /app
USER aegis
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
