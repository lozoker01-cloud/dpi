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
        minSdk = 29
        targetSdk = 34
        versionCode = 4
        versionName = "1.3.0"
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

val byedpiArm64 = file("src/main/jniLibs/arm64-v8a/libbyedpi.so")
if (!byedpiArm64.exists()) {
    val ndkRoot = listOfNotNull(
        System.getenv("ANDROID_NDK_HOME"),
        System.getenv("ANDROID_HOME")?.let { "$it/ndk" },
        "/usr/local/lib/android/sdk/ndk"
    ).map { file(it) }.firstOrNull { it.exists() }

    val clangArm64 = ndkRoot?.walkTopDown()?.firstOrNull { it.name == "aarch64-linux-android29-clang" }
    val clangArm32 = ndkRoot?.walkTopDown()?.firstOrNull { it.name == "armv7a-linux-androideabi29-clang" }

    if (clangArm64 != null && clangArm32 != null) {
        val tmpDir = file("${layout.buildDirectory.get().asFile}/byedpi-src")
        if (tmpDir.exists()) tmpDir.deleteRecursively()
        exec {
            commandLine("git", "clone", "--depth", "1", "https://github.com/hufrea/byedpi.git", tmpDir.absolutePath)
        }
        val srcs = listOf("main.c", "proxy.c", "desync.c", "conev.c", "extend.c", "mpool.c", "packets.c")
            .map { file("${tmpDir.absolutePath}/$it").absolutePath }

        byedpiArm64.parentFile.mkdirs()
        exec {
            commandLine(
                listOf(clangArm64.absolutePath, "-O2", "-fPIE", "-pie", "-pthread", "-D_GNU_SOURCE", "-Wl,-z,max-page-size=16384") +
                    srcs + listOf("-o", byedpiArm64.absolutePath)
            )
        }

        val byedpiArm32 = file("src/main/jniLibs/armeabi-v7a/libbyedpi.so")
        byedpiArm32.parentFile.mkdirs()
        exec {
            commandLine(
                listOf(clangArm32.absolutePath, "-O2", "-fPIE", "-pie", "-pthread", "-D_GNU_SOURCE") +
                    srcs + listOf("-o", byedpiArm32.absolutePath)
            )
        }
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
