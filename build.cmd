@echo off
rem ============================================================================
rem MyVault 构建入口（Windows / cmd）
rem
rem 用法： build.cmd assembleDebug | test | lint | clean
rem
rem 说明：`build.cmd test` 默认执行纯 JVM 单元测试（154 个用例，秒级完成）；
rem       加 -PwithRobolectric 可额外执行 Robolectric 集成测试（首次需联网下载运行时镜像）。
rem
rem JDK 要求：**17 ~ 22**。
rem   - AGP 8.5.2 要求 JDK 17+
rem   - 本工程使用 Gradle 8.9，它**不支持 JDK 23+**（JDK 25 会直接 BUILD FAILED）
rem   - 因此本脚本会自动跳过 Android Studio 新版自带的 JBR（可能是 23/25）
rem
rem 查找顺序（第一个版本合规的胜出）：
rem   1. 环境变量 MYVAULT_JDK      —— 手动指定，优先级最高
rem   2. 环境变量 JAVA_HOME
rem   3. 常见安装位置（Adoptium / Microsoft / Java / Android Studio JBR）
rem 若都不可用，请安装 JDK 17~22 并设置 JAVA_HOME。
rem ============================================================================
setlocal enabledelayedexpansion

set "PROJECT_ROOT=%~dp0"
set "ANDROID_SDK=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_HOME=%ANDROID_SDK%"
set "ANDROID_SDK_ROOT=%ANDROID_SDK%"

rem ---------------------------------------------------------------- 挑选 JDK

set "JDK_CANDIDATES="
if defined MYVAULT_JDK set "JDK_CANDIDATES=!JDK_CANDIDATES!"%MYVAULT_JDK%" "
if defined JAVA_HOME   set "JDK_CANDIDATES=!JDK_CANDIDATES!"%JAVA_HOME%" "

for %%B in (
  "%ProgramFiles%\Eclipse Adoptium"
  "%ProgramFiles%\Microsoft\jdk"
  "%ProgramFiles%\Java"
  "%ProgramFiles%\Android\Android Studio\jbr"
  "%LOCALAPPDATA%\Programs\Eclipse Adoptium"
) do (
  if exist %%B (
    for /d %%D in (%%B\*) do set "JDK_CANDIDATES=!JDK_CANDIDATES!"%%~fD" "
  )
)

set "JAVA_HOME="
for %%J in (!JDK_CANDIDATES!) do (
  if not defined JAVA_HOME (
    if exist "%%~J\bin\javac.exe" (
      rem 取版本号首段。javac -version 输出到 stderr：
      rem   javac 17.0.20.1      -> major 17
      rem   javac 22.0.1         -> major 22
      rem   javac 25.0.3         -> major 25（Gradle 8.9 不支持，跳过）
      for /f "tokens=2" %%V in ('"%%~J\bin\javac.exe" -version 2^>^&1') do (
        for /f "tokens=1 delims=." %%M in ("%%V") do set "JDK_MAJOR=%%M"
      )
      if defined JDK_MAJOR (
        if !JDK_MAJOR! GEQ 17 if !JDK_MAJOR! LEQ 22 (
          set "JAVA_HOME=%%~J"
          echo [MyVault] 选用 JDK !JDK_MAJOR!：%%~J
        ) else (
          echo [MyVault] 跳过 JDK !JDK_MAJOR!（不在 17~22 范围）：%%~J
        )
      )
    )
  )
)

if not defined JAVA_HOME (
  rem 注意：下面这些 echo 一律写成 `echo(` 而不是 `echo`。
  rem 因为文本里可能含 Windows 路径 —— 若写成 `echo D:\tools\jdk`，
  rem cmd 会把 `\t` 之类误解析成重定向，从而在本目录**意外创建垃圾文件**（踩过一次）。
  echo([ERROR] 未找到可用的 JDK（需要 17 ~ 22）。
  echo(        已检查：MYVAULT_JDK、JAVA_HOME、以及常见安装目录。
  echo(        请安装 JDK 17~22 后设置 JAVA_HOME，或用 MYVAULT_JDK 直接指定，例如：
  echo(            set MYVAULT_JDK=C:\Java\jdk-17
  echo(        注意：Gradle 8.9 不支持 JDK 23+，Android Studio 新版自带的 JBR 可能过新。
  exit /b 1
)

rem ---------------------------------------------------------------- 挑选 Gradle

rem 优先使用 Gradle wrapper；若未下载分发则回退到本地 Gradle 缓存
set "GRADLE_CMD="
if exist "%PROJECT_ROOT%gradle\wrapper\gradle-wrapper.jar" (
  set "GRADLE_CMD=%PROJECT_ROOT%gradlew.bat"
)
if not defined GRADLE_CMD (
  for /d %%D in ("%USERPROFILE%\.gradle\wrapper\dists\gradle-8.9-bin\*") do (
    if exist "%%D\gradle-8.9\bin\gradle.bat" set "GRADLE_CMD=%%D\gradle-8.9\bin\gradle.bat"
  )
)
if not defined GRADLE_CMD (
  echo [ERROR] 未找到 Gradle 8.9，请联网执行 gradlew 或安装 Gradle 8.9。
  exit /b 1
)

if "%~1"=="" (
  set "GRADLE_TASKS=assembleDebug"
) else (
  set "GRADLE_TASKS=%*"
)

echo [MyVault] JAVA_HOME=%JAVA_HOME%
echo [MyVault] ANDROID_SDK=%ANDROID_SDK%
echo [MyVault] GRADLE=%GRADLE_CMD%
echo [MyVault] TASKS=%GRADLE_TASKS%
echo.

call "%GRADLE_CMD%" %GRADLE_TASKS% --console=plain
exit /b %ERRORLEVEL%
