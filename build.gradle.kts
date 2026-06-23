plugins {
    id("java-library")
    id("org.springframework.boot") version "4.1.0" apply false
    id("io.spring.dependency-management") version "1.1.7"
    id("com.diffplug.spotless") version "7.0.2"
    id("checkstyle")
    id("jacoco")
    id("com.vanniktech.maven.publish") version "0.34.0"
}

group = "io.github.sequelcore"
version = "7.0.0"

val hasSigningConfiguration = providers.gradleProperty("signingInMemoryKey").isPresent
    || providers.gradleProperty("signing.secretKeyRingFile").isPresent
    || providers.environmentVariable("ORG_GRADLE_PROJECT_signingInMemoryKey").isPresent

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

repositories {
    mavenCentral()
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:4.1.0")
    }
}

dependencies {
    // Spring Boot (provided - user brings these)
    compileOnly("org.springframework.boot:spring-boot-starter-security")
    compileOnly("org.springframework.boot:spring-boot-starter-web")

    // Auto-configuration
    implementation("org.springframework.boot:spring-boot-autoconfigure")
    implementation("org.springframework.boot:spring-boot-jackson")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    // JWT - api scope exposes Claims, JwtException to consumers
    api("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

    // Cache (for token blacklist)
    implementation("com.github.ben-manes.caffeine:caffeine:3.2.4")

    // Validation
    implementation("jakarta.validation:jakarta.validation-api")

    // Lombok
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")

    // Testing
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security")
    testImplementation("org.springframework.boot:spring-boot-starter-validation")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.springframework.boot:spring-boot-starter-restclient")
    testImplementation("org.springframework.boot:spring-boot-resttestclient")
    testImplementation("org.springframework.boot:spring-boot-starter-web")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testCompileOnly("org.projectlombok:lombok")
    testAnnotationProcessor("org.projectlombok:lombok")
}

// Spotless configuration (Google Java Format)
spotless {
    java {
        googleJavaFormat("1.28.0")
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
    }
}

// Checkstyle configuration
checkstyle {
    toolVersion = "13.6.0"
    configFile = file("${rootDir}/config/checkstyle/checkstyle.xml")
    isIgnoreFailures = false
}

// JaCoCo configuration
jacoco {
    toolVersion = "0.8.14"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required = true
        html.required = true
    }
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule {
            limit {
                minimum = "0.80".toBigDecimal()
            }
        }
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.add("-parameters")
}

// Quality check task
tasks.register("qualityCheck") {
    dependsOn("spotlessCheck", "checkstyleMain", "test", "jacocoTestCoverageVerification")
    description = "Runs all quality checks"
    group = "verification"
}

// Maven Central Publishing via vanniktech plugin (v0.34.0+)
mavenPublishing {
    publishToMavenCentral(automaticRelease = true)
    if (hasSigningConfiguration) {
        signAllPublications()
    }

    coordinates(group.toString(), "vigil-spring-boot-starter", version.toString())

    pom {
        name.set("Vigil")
        description.set("Opinionated JWT authentication starter for Spring Boot")
        inceptionYear.set("2025")
        url.set("https://github.com/sequelcore/vigil")

        licenses {
            license {
                name.set("Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0")
                distribution.set("repo")
            }
        }

        developers {
            developer {
                id.set("sequelcore")
                name.set("Sequel")
                url.set("https://github.com/sequelcore")
            }
        }

        scm {
            url.set("https://github.com/sequelcore/vigil")
            connection.set("scm:git:git://github.com/sequelcore/vigil.git")
            developerConnection.set("scm:git:ssh://github.com/sequelcore/vigil.git")
        }
    }
}

tasks.withType<Javadoc> {
    options.encoding = "UTF-8"
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}
