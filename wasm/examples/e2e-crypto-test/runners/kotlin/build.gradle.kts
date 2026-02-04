plugins {
    kotlin("jvm") version "1.9.22"
    application
}

group = "com.flatbuffers.e2e"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // Chicory WASM runtime (pure JVM)
    implementation("com.dylibso.chicory:runtime:1.5.3")
    implementation("com.dylibso.chicory:wasi:1.5.3")

    // FlatBuffers runtime
    implementation("com.google.flatbuffers:flatbuffers-java:24.12.23")

    // JSON parsing
    implementation("com.google.code.gson:gson:2.10.1")

    // Kotlin stdlib
    implementation(kotlin("stdlib"))
}

application {
    mainClass.set("com.flatbuffers.e2e.TestRunnerKt")
}

kotlin {
    jvmToolchain(21)
}

tasks.named<JavaExec>("run") {
    workingDir = projectDir
}
