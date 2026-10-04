@echo off
rem ============================================================================
rem gradlew 兼容入口（Windows）
rem
rem 本工程不需要 gradle-wrapper.jar：脚本会优先使用 Gradle 官方 wrapper 分发的
rem 本地缓存（%USERPROFILE%\.gradle\wrapper\dists），因此**离线也能构建**。
rem 若本机确实没有缓存，请联网执行 `gradle wrapper` 生成标准 wrapper，
rem 或安装 Gradle 8.9 后重试。
rem
rem 实际逻辑集中在 build.cmd，本文件保持标准 gradlew 的调用手感。
rem ============================================================================
setlocal
call "%~dp0build.cmd" %*
exit /b %ERRORLEVEL%
