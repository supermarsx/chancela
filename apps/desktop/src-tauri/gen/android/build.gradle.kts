buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:9.3.0")
        // Kotlin 2.4.10 turns the deprecated Android DSL still used by Tauri
        // 2.11.5's published mobile modules into script-compilation errors.
        // Keep Tauri's newest compatible Kotlin line until those upstream
        // modules migrate to compilerOptions and AGP's public DSL.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.21")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

tasks.register("clean").configure {
    delete("build")
}
