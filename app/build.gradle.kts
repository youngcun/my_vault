plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.myvault.password"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.myvault.password"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        // 只保留一个测试 runner，不引入任何需要联网的库
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // 密码生成器默认策略（可在应用内调整）
        buildConfigField("int", "DEFAULT_PASSWORD_LENGTH", "20")
        buildConfigField("int", "MIN_PASSWORD_LENGTH", "8")
        buildConfigField("int", "MAX_PASSWORD_LENGTH", "128")
    }

    // 单一签名配置：debug 用默认调试密钥即可，release 由用户自行配置
    buildTypes {
        debug {
            isMinifyEnabled = false
            isDebuggable = true
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // 关闭 release 的调试符号，减小体积
            ndk { debugSymbolLevel = "none" }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf("-Xjvm-default=all")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/DEPENDENCIES",
                "/META-INF/LICENSE*",
                "/META-INF/NOTICE*",
                "/META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/INDEX.LIST",
                "META-INF/*.kotlin_module",
            )
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }

    sourceSets {
        getByName("test") {
            // 词表是 main 下的 Java 资源，单元测试也要能读到
            resources.srcDirs("src/main/resources", "src/test/resources")
        }
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

/**
 * 测试分层。
 *
 * 本项目把单元测试分成两层，原因很实际：
 *
 *  1. **纯 JVM 层**（默认执行）：密码学内核、口令生成器、熵估计、备份格式。
 *     这些类不依赖任何 Android 类，因此在任意 JDK 上都能秒级跑完，
 *     适合每次改动都执行。密码学逻辑正是最需要高频回归的部分。
 *
 *  2. **Robolectric 集成层**（`-PwithRobolectric` 显式开启）：字段级加密与
 *     Room 仓储的集成。它需要下载 Android 运行时镜像，首次运行耗时且依赖网络，
 *     因此不放进默认任务 —— 一个「跑不完的测试」等于没有测试。
 *     它同样是**每次功能改动都应执行**的，只是不该阻塞快速回归。
 *
 * 用法：
 *   gradlew test                          # 只跑纯 JVM 层（快）
 *   gradlew test -PwithRobolectric        # 额外跑 Robolectric 集成层
 */
val runRobolectricTests = providers.gradleProperty("withRobolectric").isPresent

tasks.withType<Test>().configureEach {
    if (!runRobolectricTests) {
        filter {
            excludeTestsMatching("com.myvault.password.data.*")
        }
    }
    // 中文测试名与断言消息需要 UTF-8，否则报告会乱码
    systemProperty("file.encoding", "UTF-8")
    systemProperty("sun.jnu.encoding", "UTF-8")
    maxHeapSize = "1g"
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = false
    }
}

// Room 导出数据库 schema：把每一版的表结构提交进版本库，
// 这样将来任何字段变更都必须写显式 Migration，不能靠「删库重建」蒙混过关。
ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
    arg("room.incremental", "true")
}

dependencies {
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    implementation(libs.androidx.biometric)
    implementation(libs.androidx.autofill)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.documentfile)

    implementation(libs.kotlinx.serialization.json)

    // Argon2id 实现（纯 Java，无 native 依赖，离线可用）
    implementation(libs.bouncycastle.prov)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.androidx.test.ext.junit)

    // 设备端（instrumentation）测试：在真实 Android 运行时上验证
    // 「创建库 → 保存条目 → 读回 → 完整性校验 → 备份往返」这一整条链路。
    // 这些行为在 JVM/Robolectric 上无法完全等价复现。
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
