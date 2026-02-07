FROM eclipse-temurin:17-jdk AS build

WORKDIR /app

COPY gradle/ gradle/
COPY gradlew settings.gradle.kts build.gradle.kts ./
RUN ./gradlew dependencies --no-daemon

COPY src/ src/
RUN ./gradlew bootJar --no-daemon

FROM eclipse-temurin:17-jre

WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]
