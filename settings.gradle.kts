pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "ic-auth-client-rs"

include(":kotlin-package:IcAuthClient")
project(":kotlin-package:IcAuthClient").projectDir = file("kotlin-package/IcAuthClient")
