import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.dpiguard.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.dpiguard.android"
        minSdk = 24
        targetSdk = 34
        versionCode = 2
        versionName = "1.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
    }
}

val hevAar = file("libs/hev-socks5-tunnel.aar")
if (!hevAar.exists()) {
    hevAar.parentFile.mkdirs()
    val client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.ALWAYS)
        .build()
    val request = HttpRequest.newBuilder()
        .uri(URI.create("https://github.com/heiher/hev-socks5-tunnel/releases/download/2.20.0/hev-socks5-tunnel.aar"))
        .build()
    val response = client.send(request, HttpResponse.BodyHandlers.ofFile(hevAar.toPath()))
    if (response.statusCode() !in 200..299) {
        hevAar.delete()
        throw GradleException("Failed to download hev-socks5-tunnel.aar: HTTP ${response.statusCode()}")
    }
}

dependencies {
    implementation(files("libs/hev-socks5-tunnel.aar"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
