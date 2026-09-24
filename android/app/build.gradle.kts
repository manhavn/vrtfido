plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.vrtfido"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.vrtfido"
        minSdk = 28
        targetSdk = 35
        versionCode = 7
        versionName = "0.2.5"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        val keystore = System.getenv("VRTFIDO_KEYSTORE")
        val storePassword = System.getenv("VRTFIDO_KEYSTORE_PASSWORD")
        val alias = System.getenv("VRTFIDO_KEY_ALIAS")
        val keyPassword = System.getenv("VRTFIDO_KEY_PASSWORD")
        if (!keystore.isNullOrBlank() && !storePassword.isNullOrBlank() &&
            !alias.isNullOrBlank() && !keyPassword.isNullOrBlank()) {
            create("vrtfidoRelease") {
                storeFile = file(keystore)
                this.storePassword = storePassword
                keyAlias = alias
                this.keyPassword = keyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfigs.findByName("vrtfidoRelease")?.let { signingConfig = it }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDir("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")

    // Credential Manager API & Biometrics
    implementation("androidx.credentials:credentials:1.3.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.3.0")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")

    // Coroutines & Networking (Localhost communication)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
