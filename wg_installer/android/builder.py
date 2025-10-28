from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from ..core.runner import Runner
from ..core.config import Config
from ..core.state import StateDB


@dataclass
class AndroidBuildConfig:
    repo_url: str = "https://github.com/ClusterM/wg-obfuscator-android.git"
    branch: str = "master"
    build_dir: Path = Path("/tmp/wg-obfuscator-android-build")
    apk_output_dir: Optional[Path] = None
    java_home: Optional[str] = None
    gradle_home: Optional[str] = None


class AndroidAPKBuilder:
    def __init__(self, config: AndroidBuildConfig, runner: Runner, state: StateDB):
        self.config = config
        self.runner = runner
        self.state = state

    def build_apk(self, server_config: Config) -> Path:
        # Clone or update the repo
        if not self.config.build_dir.exists():
            self.runner.run(["git", "clone", "--branch", self.config.branch, self.config.repo_url, str(self.config.build_dir)], check=True)
        else:
            self.runner.run(["git", "-C", str(self.config.build_dir), "pull"], check=True)

        # Inject server config into the Android app
        config_file = self.config.build_dir / "app/src/main/res/raw/server_config.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w') as f:
            f.write(server_config.model_dump_json())

        # Build the APK
        env = {}
        if self.config.java_home:
            env["JAVA_HOME"] = self.config.java_home
        if self.config.gradle_home:
            env["GRADLE_HOME"] = self.config.gradle_home

        # If JAVA_HOME is not set in config, try to detect java on PATH to give a
        # clearer error message before invoking gradle.
        if not self.config.java_home:
            try:
                jr = self.runner.run(["java", "-version"], check=False, capture=True)
                if jr.returncode != 0:
                    raise RuntimeError()
            except Exception:
                raise SystemExit(
                    "Java not found. Install a JDK (e.g. `sudo apt-get install default-jdk`) or set JAVA_HOME.\n"
                    "Example: sudo apt-get update && sudo apt-get install -y default-jdk\n"
                    "Or set JAVA_HOME to your JDK path and re-run."
                )

        # Check for Android SDK: either ANDROID_HOME env var or sdk.dir in local.properties
        android_sdk_found = False
        local_props = self.config.build_dir / "local.properties"
        if local_props.exists():
            with open(local_props, 'r') as f:
                for line in f:
                    if line.strip().startswith("sdk.dir="):
                        sdk_path = line.strip().split("=", 1)[1].strip()
                        if Path(sdk_path).exists():
                            android_sdk_found = True
                            break
        if not android_sdk_found and "ANDROID_HOME" in env:
            if Path(env["ANDROID_HOME"]).exists():
                android_sdk_found = True
        if not android_sdk_found:
            # Auto-install Android SDK
            print("[wg-installer] Android SDK not found. Installing automatically...")
            sdk_dir = Path("/opt/android-sdk")
            sdk_dir.mkdir(parents=True, exist_ok=True)
            cmdline_tools_zip = "/tmp/cmdline-tools.zip"
            cmdline_tools_url = "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
            self.runner.run(["curl", "-L", "-o", cmdline_tools_zip, cmdline_tools_url], check=True)
            self.runner.run(["unzip", "-q", cmdline_tools_zip, "-d", str(sdk_dir)], check=True)
            # Move to cmdline-tools/latest
            latest_dir = sdk_dir / "cmdline-tools" / "latest"
            latest_dir.mkdir(parents=True, exist_ok=True)
            import shutil
            for item in (sdk_dir / "cmdline-tools").iterdir():
                if item.name != "latest":
                    shutil.move(str(item), str(latest_dir))
            env["ANDROID_HOME"] = str(sdk_dir)
            # Install platform-tools and platform
            sdkmanager = sdk_dir / "cmdline-tools" / "latest" / "bin" / "sdkmanager"
            self.runner.run(["yes", "|", str(sdkmanager), "--licenses"], env=env, check=False)  # Accept licenses
            self.runner.run([str(sdkmanager), "platform-tools", "platforms;android-34"], env=env, check=True)
            android_sdk_found = True

        # Ensure the gradle wrapper is executable; some git checkouts don't preserve the
        # executable bit. Try to chmod it, then run. If chmod doesn't help, fall back to
        # invoking it via the shell (sh ./gradlew ...) which doesn't require the exec bit.
        gradlew_path = self.config.build_dir / "gradlew"
        if gradlew_path.exists():
            try:
                # best-effort: set executable bit
                self.runner.run(["chmod", "+x", str(gradlew_path)], check=False)
            except Exception:
                pass
        # If the Android SDK isn't present, try to install the command-line tools and
        # a minimal set of packages automatically (best-effort).
        sdk_dir = Path("/opt/android-sdk")
        sdkmanager = sdk_dir / "cmdline-tools" / "latest" / "bin" / "sdkmanager"
        if not sdk_dir.exists() or not sdkmanager.exists():
            print("[wg-installer] Android SDK not found. Installing automatically...")
            # create target dir
            self.runner.run(["mkdir", "-p", str(sdk_dir)], check=False)
            # download commandline tools
            dl_url = "https://dl.google.com/android/repository/commandlinetools-linux-latest.zip"
            zip_tmp = Path("/tmp/cmdline-tools.zip")
            # fetch and unpack
            self.runner.run(["bash", "-lc", f"curl -fSL {dl_url} -o {zip_tmp} && rm -rf /tmp/cmdline-tools-extract && mkdir -p /tmp/cmdline-tools-extract && unzip -q {zip_tmp} -d /tmp/cmdline-tools-extract && mkdir -p {sdk_dir}/cmdline-tools/latest && mv /tmp/cmdline-tools-extract/cmdline-tools/* {sdk_dir}/cmdline-tools/latest"], check=True)
            # make sdkmanager executable
            self.runner.run(["chmod", "+x", str(sdk_dir / "cmdline-tools" / "latest" / "bin" / "sdkmanager")], check=False)
            sdkmanager = sdk_dir / "cmdline-tools" / "latest" / "bin" / "sdkmanager"

            # Install core packages. Use platform 33 as a reasonable default; if project
            # requires a different API you may need to adjust.
            pkgs = ["platform-tools", "platforms;android-33", "build-tools;33.0.2"]
            # Accept licenses non-interactively
            for pkg in pkgs:
                print(f"[wg-installer] Installing Android SDK package: {pkg}")
                # sdkmanager may require JAVA_HOME; assume JDK is already installed by ensure_packages
                self.runner.run(["bash", "-lc", f"{sdkmanager} \"{pkg}\""], check=True)
            # Accept licenses
            try:
                self.runner.shell(f"yes | {sdkmanager} --licenses", check=True)
            except Exception:
                # Some systems use a different yes; fallback to python-driven acceptance
                self.runner.run(["bash", "-lc", f"printf 'y\n' | {sdkmanager} --licenses"], check=False)
            # write local.properties
            local_props = self.config.build_dir / "local.properties"
            try:
                local_props.write_text(f"sdk.dir={str(sdk_dir)}\n", encoding="utf-8")
            except Exception:
                pass

        # Run gradle with limited parallelism to avoid freezing the host
        # Prepare constrained environment
        import os
        env2 = os.environ.copy()
        env2.update(env)
        env2.update({
            "CMAKE_BUILD_PARALLEL_LEVEL": "1",
            "NINJAFLAGS": "-j1",
            "ANDROID_NDK_BUILD_JOBS": "1",
            "GRADLE_USER_HOME": os.path.expanduser("~/.gradle"),
        })

        cmd = [
            "bash", "-lc",
            'nice -n 10 ionice -c3 "' + str(gradlew_path) + '" assembleRelease --no-daemon --no-parallel --max-workers=1'
        ]
        try:
            self.runner.run(cmd, cwd=self.config.build_dir, env=env2, check=True)
        except Exception:
            # final fallback: try invoking via sh if exec fails
            self.runner.run(["bash", "-lc", f"nice -n 10 ionice -c3 sh {str(gradlew_path)} assembleRelease --no-daemon --no-parallel --max-workers=1"], cwd=self.config.build_dir, env=env2, check=True)

        # Find the built APK
        apk_path = self.config.build_dir / "app/build/outputs/apk/release/app-release.apk"
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found at {apk_path}")

        # Copy to output dir if specified
        if self.config.apk_output_dir:
            self.config.apk_output_dir.mkdir(parents=True, exist_ok=True)
            output_path = self.config.apk_output_dir / "wg-obfuscator-client.apk"
            import shutil
            shutil.copy2(apk_path, output_path)
            return output_path
        return apk_path