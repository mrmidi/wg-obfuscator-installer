from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from ..core.runner import Runner
from ..core.config import Config
from ..core.state import StateDB


@dataclass
class AndroidBuildConfig:
    repo_url: str = "https://github.com/ClusterM/wg-obfuscator-android.git"
    branch: str = "main"
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
        self.runner.run(["./gradlew", "assembleRelease"], cwd=self.config.build_dir, env=env, check=True)

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