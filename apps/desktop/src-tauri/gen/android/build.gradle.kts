buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:9.3.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.21")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }

    // Tauri 2.11.5's embedded Android modules declare older AndroidX, Material,
    // test, and Jackson versions. Resolve the entire included build to the same
    // current stable dependency set used by the application module.
    configurations.configureEach {
        resolutionStrategy {
            force("androidx.core:core-ktx:1.19.0")
            force("androidx.appcompat:appcompat:1.7.1")
            force("androidx.browser:browser:1.10.0")
            force("com.google.android.material:material:1.14.0")
            force("com.fasterxml.jackson.core:jackson-databind:2.22.1")
            force("androidx.test.ext:junit:1.3.0")
            force("androidx.test.espresso:espresso-core:3.7.0")
        }
    }
}

tasks.register("clean").configure {
    delete("build")
}
