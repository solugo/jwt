import org.jetbrains.kotlin.gradle.dsl.KotlinJvmCompile

plugins {
    kotlin("jvm") version "1.4.10"
    id("maven-publish")
}

group = "de.solugo.jwt"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.11.3")

    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.7.0")
}

publishing {
    publications {
        create("lib", MavenPublication::class.java) {
            from(components.getByName("kotlin"))
        }
    }
}

tasks.withType(KotlinJvmCompile::class.java).all {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.withType(Test::class.java).all {
    useJUnitPlatform()
}