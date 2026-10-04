# ============================================================================
# MyVault 混淆 / 优化规则
# ============================================================================
# 保留 Kotlin 元数据与序列化器的必要信息
-keepattributes *Annotation*, InnerClasses, Signature, SourceFile, LineNumberTable
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations

# BouncyCastle：Argon2id 依赖反射加载算法实现，必须完整保留
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# Room 生成的实现类
-keep class * extends androidx.room.RoomDatabase { <init>(); }
-keep @androidx.room.Entity class * { *; }
-dontwarn androidx.room.paging.**

# kotlinx.serialization：保留 @Serializable 类的合成序列化器
-keepattributes RuntimeVisibleAnnotations
-keepclassmembers class **$$serializer { *; }
-keepclasseswithmembers class * {
    kotlinx.serialization.KSerializer serializer(...);
}

# 自动填充服务与无障碍相关类由系统实例化，不能被重命名
-keep class * extends android.service.autofill.AutofillService { *; }
-keep class * extends android.app.Service { *; }
-keep class * extends android.content.ContentProvider { *; }
-keep class * extends androidx.biometric.** { *; }

# 去掉日志，避免敏感信息落入 logcat（配合发布版安全要求）
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
}

# 保留行号便于崩溃定位，但不保留调试信息
-renamesourcefileattribute SourceFile
