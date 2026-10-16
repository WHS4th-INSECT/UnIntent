"""Command-line entry point for UnIntent."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.Analyzer import (
    DEFAULT_STATIC_MAX_CALL_DEPTH,
    DEFAULT_STATIC_TIMEOUT_SECONDS,
    Analyzer,
)


class UnIntentCLI:
    """Parse UnIntent options and start the analyzer."""

    DOWNLOAD_OPTIONS = {"-d", "--download"}
    TOP100_OPTIONS = {"-t", "--top-100"}
    HELP_OPTIONS = {"-h", "--help"}
    TIMEOUT_OPTION = "--time-out"
    DEPTH_OPTION = "--depth"

    def __init__(self, arguments: list[str] | None = None):
        self.arguments = list(sys.argv[1:] if arguments is None else arguments)
        self.download = False
        self.top100 = False
        self.help = False
        self.timeout_seconds = DEFAULT_STATIC_TIMEOUT_SECONDS
        self.max_call_depth = DEFAULT_STATIC_MAX_CALL_DEPTH

    def run(self) -> int:
        """Parse options and run the selected analysis mode."""
        self.print_banner()
        try:
            self.parse_options()
        except ValueError as exception:
            print(f"[ERROR] {exception}", file=sys.stderr)
            self.print_help(file=sys.stderr)
            return 2

        if self.help:
            self.print_help()
            return 0

        try:
            return self.create_analyzer().run()
        except KeyboardInterrupt:
            print("\n[INTERRUPTED] Analysis cancelled.", file=sys.stderr)
            return 130
        except (OSError, RuntimeError, TypeError, ValueError) as exception:
            print(f"[ERROR] {exception}", file=sys.stderr)
            return 1

    def parse_options(self) -> None:
        """Parse supported flags without an external CLI library."""
        index = 0
        while index < len(self.arguments):
            option = self.arguments[index]
            if option in self.DOWNLOAD_OPTIONS:
                self.download = True
            elif option in self.TOP100_OPTIONS:
                self.top100 = True
            elif option in self.HELP_OPTIONS:
                self.help = True
            elif option == self.TIMEOUT_OPTION:
                value = self.option_value(option, index)
                self.timeout_seconds = self.parse_timeout(value)
                index += 1
            elif option == self.DEPTH_OPTION:
                value = self.option_value(option, index)
                self.max_call_depth = self.parse_depth(value)
                index += 1
            else:
                raise ValueError(f"Unknown option: {option}")
            index += 1

        if self.download and self.top100:
            raise ValueError("--download and --top-100 cannot be used together")

    def option_value(self, option: str, option_index: int) -> str:
        """Return the value following an option that requires one."""
        value_index = option_index + 1
        if value_index >= len(self.arguments):
            raise ValueError(f"{option} requires a value")
        return self.arguments[value_index]

    def parse_timeout(self, value: str) -> float:
        """Parse a positive static-analysis timeout in seconds."""
        try:
            timeout_seconds = float(value)
        except ValueError as exception:
            raise ValueError("--time-out must be a number") from exception
        if timeout_seconds <= 0:
            raise ValueError("--time-out must be greater than zero")
        return timeout_seconds

    def parse_depth(self, value: str) -> int:
        """Parse a non-negative static-analysis call depth."""
        try:
            max_call_depth = int(value)
        except ValueError as exception:
            raise ValueError("--depth must be an integer") from exception
        if max_call_depth < 0:
            raise ValueError("--depth must not be negative")
        return max_call_depth

    def create_analyzer(self) -> Analyzer:
        """Create the analyzer for the selected acquisition mode."""
        return Analyzer(
            download=self.download,
            top100=self.top100,
            timeout_seconds=self.timeout_seconds,
            max_call_depth=self.max_call_depth,
        )

    def print_banner(self) -> None:
        """Print the UnIntent banner."""
        banner = (
            "██╗   ██╗███╗   ██╗██╗███╗   ██╗████████╗███████╗███╗   ██╗████████╗",
            "██║   ██║████╗  ██║██║████╗  ██║╚══██╔══╝██╔════╝████╗  ██║╚══██╔══╝",
            "██║   ██║██╔██╗ ██║██║██╔██╗ ██║   ██║   █████╗  ██╔██╗ ██║   ██║",
            "██║   ██║██║╚██╗██║██║██║╚██╗██║   ██║   ██╔══╝  ██║╚██╗██║   ██║",
            "╚██████╔╝██║ ╚████║██║██║ ╚████║   ██║   ███████╗██║ ╚████║   ██║",
            " ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝   ╚══════╝",
        )
        print()
        for line in banner:
            print(line)
        print("          Reverse-Tracing Android Intent Analyzer\n")

    def print_help(self, file: object = sys.stdout) -> None:
        """Print supported command-line options."""
        print(
            "Usage: python UnIntent.py [--download | --top-100] "
            "[--time-out SECONDS] [--depth DEPTH]",
            file=file,
        )
        print(file=file)
        print("Options:", file=file)
        print("  -d, --download  Download packages from data/apks/target.txt", file=file)
        print("  -t, --top-100   Download the Google Play Top 100", file=file)
        print(
            "  --time-out SEC  Static-analysis timeout (default: unlimited)",
            file=file,
        )
        print(
            f"  --depth DEPTH   Maximum call depth (default: "
            f"{DEFAULT_STATIC_MAX_CALL_DEPTH})",
            file=file,
        )
        print("  -h, --help      Show this help message", file=file)
        print(file=file)
        print("Without an option, analyze APKs in data/apks/targets.", file=file)


if __name__ == "__main__":
    raise SystemExit(UnIntentCLI().run())
