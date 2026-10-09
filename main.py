import argparse
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional



logging.basicConfig(
    filename="log_analyzer_internal.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


LINE = "-" * 70

LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>.*?)\]\s+"
    r"\[(?P<log_level>.*?)\]\s+"
    r"\[(?P<session_id>.*?)\]\s+"
    r"\[(?P<user>.*?)\]\s+"
    r"\[(?P<client_ip>.*?)\]\s+"
    r"\[(?P<module>.*?)\]\s*-\s*"
    r"(?P<message>.*)"
)

TIME_PATTERN = re.compile(
    r"(\d+(?:\.\d+)?)\s*(milliseconds?|ms|seconds?|secs?|s)\b",
    re.IGNORECASE,
)

AMOUNT_PATTERN = re.compile(
    r"(?:amount\s*(?:is|:|=)?\s*\$?\s*|\$\s*)"
    r"(\d+(?:,\d{3})*(?:\.\d+)?)",
    re.IGNORECASE,
)


# ------------------------------------------------------------
# Data 
# ------------------------------------------------------------

@dataclass
class LogEntry:
    """Represent one valid bank database server log entry."""

    timestamp: datetime
    log_level: str
    session_id: str
    user: str
    client_ip: str
    module: str
    message: str


# ------------------------------------------------------------
# Parser
# ------------------------------------------------------------

class LogParser:
    """Read a log file and convert valid lines into LogEntry objects."""

    def __init__(self) -> None:
        self.total_lines = 0
        self.invalid_lines = 0

    def parse_file(self, filename: str) -> list[LogEntry]:
        """
        Parse a bank-server log file.
        """

        entries: list[LogEntry] = []

        # Reset counters every time a new file is parsed.
        self.total_lines = 0
        self.invalid_lines = 0

        with open(filename, "r", encoding="utf-8") as file:
            for line_number, raw_line in enumerate(file, start=1):
                self.total_lines += 1
                line = raw_line.strip()

                # Empty lines are invalid log records.
                if not line:
                    self.invalid_lines += 1
                    logging.warning(
                        "Empty line skipped at line %d in %s",
                        line_number,
                        filename,
                    )
                    continue

                match = LOG_PATTERN.fullmatch(line)

                if not match:
                    self.invalid_lines += 1
                    logging.warning(
                        "Malformed log line skipped at line %d in %s",
                        line_number,
                        filename,
                    )
                    continue

                data = match.groupdict()

                try:
                    timestamp = datetime.strptime(
                        data["timestamp"].strip(),
                        "%Y-%m-%d %H:%M:%S",
                    )
                except ValueError:
                    self.invalid_lines += 1
                    logging.warning(
                        "Invalid timestamp skipped at line %d in %s",
                        line_number,
                        filename,
                    )
                    continue

                log_level = data["log_level"].strip().upper()
                valid_levels = {"INFO", "WARNING", "ERROR", "CRITICAL"}

                if log_level not in valid_levels:
                    self.invalid_lines += 1
                    logging.warning(
                        "Invalid log level skipped at line %d in %s",
                        line_number,
                        filename,
                    )
                    continue

                entry = LogEntry(
                    timestamp=timestamp,
                    log_level=log_level,
                    session_id=data["session_id"].strip(),
                    user=data["user"].strip(),
                    client_ip=data["client_ip"].strip(),
                    module=data["module"].strip().upper(),
                    message=data["message"].strip(),
                )

                entries.append(entry)

        return entries


# ------------------------------------------------------------
# Log Analyzer
# ------------------------------------------------------------

class LogAnalyzer:
    """Analyze parsed bank database server log entries."""

    def __init__(
        self,
        entries: list[LogEntry],
        total_lines: int,
        invalid_lines: int,
    ) -> None:
        self.entries = entries
        self.total_lines = total_lines
        self.invalid_lines = invalid_lines

    @staticmethod
    def _print_header(title: str) -> None:
        """Print a consistent report header."""

        print(LINE)
        print(title)
        print(LINE)

    # --------------------------------------------------------
    # 1. Failed Login Report
    # --------------------------------------------------------

    def failed_login_report(self) -> None:
        """
        Count failed login attempts, group them by IP and user,
        and flag IP addresses with 3 or more failures.
        """

        total = 0
        ip_count: dict[str, int] = {}
        user_count: dict[str, int] = {}

        for entry in self.entries:
            if (
                entry.module == "AUTH"
                and entry.log_level == "ERROR"
                and "failed login attempt" in entry.message.lower()
            ):
                total += 1

                ip_count[entry.client_ip] = (
                    ip_count.get(entry.client_ip, 0) + 1
                )

                user_count[entry.user] = (
                    user_count.get(entry.user, 0) + 1
                )

        self._print_header("FAILED LOGIN REPORT")
        print("Total failed attempts:", total)

        if total == 0:
            print("\nNo failed login attempts found.")
            print(LINE)
            return

        print(
            f"\n{'IP Address':<22}"
            f"{'Failed Attempts':<20}"
            f"{'Brute Force'}"
        )

        # Sort primarily by highest number of failures,
        # then alphabetically by IP for stable output.
        for ip, count in sorted(
            ip_count.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            status = "YES" if count >= 3 else "NO"
            print(f"{ip:<22}{count:<20}{status}")

        print(f"\n{'Username':<22}{'Failed Attempts'}")

        for user, count in sorted(
            user_count.items(),
            key=lambda item: (-item[1], item[0].lower()),
        ):
            print(f"{user:<22}{count}")

        print(LINE)

    # --------------------------------------------------------
    # 2. Query Activity Summary
    # --------------------------------------------------------

    def query_activity_summary(self) -> None:
        """
        Count QUERY events and classify them as
        SELECT, UPDATE, INSERT, DELETE, or Uncategorized.
        """

        query_count = {
            "SELECT": 0,
            "UPDATE": 0,
            "INSERT": 0,
            "DELETE": 0,
            "Uncategorized": 0,
        }

        total = 0

        for entry in self.entries:
            if entry.module != "QUERY":
                continue

            total += 1
            message = entry.message.upper()

            # If more than one SQL keyword appears, classify by the
            # first operation that appears in the message.
            operations: dict[str, int] = {}

            for operation in ("SELECT", "UPDATE", "INSERT", "DELETE"):
                operation_match = re.search(rf"\b{operation}\b", message)

                if operation_match:
                    operations[operation] = operation_match.start()

            if operations:
                query_type = min(operations, key=operations.get)
                query_count[query_type] += 1
            else:
                query_count["Uncategorized"] += 1

        self._print_header("QUERY ACTIVITY SUMMARY")
        print("Total query events:", total)

        if total == 0:
            print("\nNo QUERY events found.")
            print(LINE)
            return

        print(f"\n{'Query Type':<22}{'Count'}")

        for query_type, count in query_count.items():
            print(f"{query_type:<22}{count}")

        print(LINE)

    # --------------------------------------------------------
    # 3. Slow Query Detector
    # --------------------------------------------------------

    def slow_query_detector(self) -> None:
        """
        Extract WARNING entries related to slow QUERY events
        and show the user, execution time, and complete message.
        """

        slow_queries: list[tuple[LogEntry, str]] = []

        for entry in self.entries:
            if (
                entry.module == "QUERY"
                and entry.log_level == "WARNING"
                and "slow" in entry.message.lower()
            ):
                time_match = TIME_PATTERN.search(entry.message)

                if time_match:
                    execution_time = time_match.group(0)
                else:
                    execution_time = "Not found"

                slow_queries.append((entry, execution_time))

        self._print_header("SLOW QUERY DETECTOR")

        if not slow_queries:
            print("No slow queries found.")
            print(LINE)
            return

        print(
            f"{'Timestamp':<21}"
            f"{'User':<18}"
            f"{'Execution Time':<20}"
            f"{'Message'}"
        )

        for entry, execution_time in sorted(
            slow_queries,
            key=lambda item: item[0].timestamp,
        ):
            print(
                f"{entry.timestamp:%Y-%m-%d %H:%M:%S}  "
                f"{entry.user:<18}"
                f"{execution_time:<20}"
                f"{entry.message}"
            )

        print(LINE)

    # --------------------------------------------------------
    # 4. Transaction Report
    # --------------------------------------------------------

    def transaction_report(self) -> None:
        """
        Summarize TRANSACTION events:
        deposits, withdrawals, declines, rollbacks,
        and deposited/withdrawn amounts where available.

        Declined, failed, and rolled-back transaction amounts are
        excluded from deposited/withdrawn totals.
        """

        transaction_entries = [
            entry
            for entry in self.entries
            if entry.module == "TRANSACTION"
        ]

        self._print_header("TRANSACTION REPORT")

        if not transaction_entries:
            print("No transaction events found.")
            print(LINE)
            return

        deposits = 0
        withdrawals = 0
        declined = 0
        rollbacks = 0

        total_deposited = 0.0
        total_withdrawn = 0.0

        for entry in transaction_entries:
            message = entry.message.lower()

            is_declined = (
                "declined" in message
                or "decline" in message
            )

            is_failed = "failed" in message

            is_rollback = (
                "rollback" in message
                or "rolled back" in message
            )

            if is_declined:
                declined += 1

            if is_rollback:
                rollbacks += 1

            if "deposit" in message:
                deposits += 1

                if not is_declined and not is_failed and not is_rollback:
                    amount_match = AMOUNT_PATTERN.search(entry.message)

                    if amount_match:
                        amount_str = amount_match.group(1).replace(",", "")
                        total_deposited += float(amount_str)

            if "withdraw" in message or "withdrew" in message:
                withdrawals += 1

                if not is_declined and not is_failed and not is_rollback:
                    amount_match = AMOUNT_PATTERN.search(entry.message)

                    if amount_match:
                        amount_str = amount_match.group(1).replace(",", "")
                        total_withdrawn += float(amount_str)

        print(f"{'Transaction Type':<26}{'Count'}")
        print(f"{'Deposits':<26}{deposits}")
        print(f"{'Withdrawals':<26}{withdrawals}")
        print(f"{'Declined':<26}{declined}")
        print(f"{'Rollbacks':<26}{rollbacks}")

        print(f"\n{'Amount Type':<26}{'Total'}")
        print(f"{'Deposited':<26}{total_deposited:.2f}")
        print(f"{'Withdrawn':<26}{total_withdrawn:.2f}")

        print(LINE)

    # --------------------------------------------------------
    # 5. Critical Events Report
    # --------------------------------------------------------

    def critical_events_report(self) -> None:
        """
        Extract all CRITICAL log entries with timestamp,
        session, user, module, and message.
        """

        critical_entries = [
            entry
            for entry in self.entries
            if entry.log_level == "CRITICAL"
        ]

        critical_entries.sort(key=lambda entry: entry.timestamp)

        self._print_header("CRITICAL EVENTS REPORT")

        if not critical_entries:
            print("No critical events found.")
            print(LINE)
            return

        print(
            f"{'Timestamp':<21}"
            f"{'Session ID':<18}"
            f"{'User':<15}"
            f"{'Module':<16}"
            f"{'Message'}"
        )

        for entry in critical_entries:
            print(
                f"{entry.timestamp:%Y-%m-%d %H:%M:%S}  "
                f"{entry.session_id:<18}"
                f"{entry.user:<15}"
                f"{entry.module:<16}"
                f"{entry.message}"
            )

        print(LINE)

    # --------------------------------------------------------
    # 6. User Activity Report
    # --------------------------------------------------------

    def user_activity_report(
        self,
        username: Optional[str] = None,
    ) -> None:
        """
        Display all actions performed by a given user
        in chronological order.

        Username matching is case-insensitive.
        """

        if username is None:
            username = input("Enter username: ").strip()
        else:
            username = username.strip()

        self._print_header("USER ACTIVITY REPORT")

        if not username:
            print("Error: Username cannot be empty.")
            print(LINE)
            return

        user_entries = [
            entry
            for entry in self.entries
            if entry.user.lower() == username.lower()
        ]

        user_entries.sort(key=lambda entry: entry.timestamp)

        if not user_entries:
            print("No activity found for user:", username)
            print(LINE)
            return

        print("Username:", username)

        print(
            f"\n{'Timestamp':<21}"
            f"{'Session ID':<18}"
            f"{'IP Address':<18}"
            f"{'Module':<16}"
            f"{'Level':<12}"
            f"{'Message'}"
        )

        for entry in user_entries:
            print(
                f"{entry.timestamp:%Y-%m-%d %H:%M:%S}  "
                f"{entry.session_id:<18}"
                f"{entry.client_ip:<18}"
                f"{entry.module:<16}"
                f"{entry.log_level:<12}"
                f"{entry.message}"
            )

        print(LINE)

    # --------------------------------------------------------
    # 7. Login/Logout Session Report
    # --------------------------------------------------------

    def login_logout_session_report(self) -> None:
        """
        List authenticated sessions and show login time,
        logout time when available, and session duration.

        Reused session IDs are handled correctly by storing
        each login as a separate session record.
        """

        sessions: list[dict[str, object]] = []
        active_sessions: dict[str, dict[str, object]] = {}

        # Work chronologically so login/logout pairing is consistent.
        auth_entries = sorted(
            (
                entry
                for entry in self.entries
                if entry.module == "AUTH"
            ),
            key=lambda entry: entry.timestamp,
        )

        for entry in auth_entries:
            msg = entry.message.lower()

            # Successful login
            if (
                (
                    "successful login" in msg
                    or "login successful" in msg
                    or "logged in" in msg
                    or "signed in" in msg
                )
                and "failed" not in msg
            ):
                session = {
                    "session_id": entry.session_id,
                    "user": entry.user,
                    "login": entry.timestamp,
                    "logout": None,
                    "duration": None,
                }

                sessions.append(session)
                active_sessions[entry.session_id] = session

            # Logout
            elif (
                "logout" in msg
                or "logged out" in msg
                or "signed out" in msg
            ):
                if entry.session_id in active_sessions:
                    session = active_sessions[entry.session_id]
                    login_time = session["login"]

                    if (
                        isinstance(login_time, datetime)
                        and entry.timestamp >= login_time
                    ):
                        session["logout"] = entry.timestamp
                        session["duration"] = (
                            entry.timestamp - login_time
                        )

                        # The session is now closed.
                        del active_sessions[entry.session_id]

                    else:
                        logging.warning(
                            "Logout before login for session %s",
                            entry.session_id,
                        )

                else:
                    logging.warning(
                        "Logout without matching login: session %s",
                        entry.session_id,
                    )

        self._print_header("LOGIN/LOGOUT SESSION REPORT")

        if not sessions:
            print("No sessions found.")
            print(LINE)
            return

        print(
            f"{'Session ID':<18}"
            f"{'User':<16}"
            f"{'Login Time':<22}"
            f"{'Logout Time':<22}"
            f"{'Duration'}"
        )

        sessions.sort(
            key=lambda session: session["login"]
        )

        for session in sessions:
            login_value = session["login"]
            logout_value = session["logout"]
            duration_value = session["duration"]

            login_text = (
                login_value.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(login_value, datetime)
                else "Not available"
            )

            logout_text = (
                logout_value.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(logout_value, datetime)
                else "Not available"
            )

            duration_text = (
                self._format_duration(duration_value)
                if isinstance(duration_value, timedelta)
                else "Not available"
            )

            print(
                f"{str(session['session_id']):<18}"
                f"{str(session['user']):<16}"
                f"{login_text:<22}"
                f"{logout_text:<22}"
                f"{duration_text}"
            )

        print(LINE)

    @staticmethod
    def _format_duration(duration: timedelta) -> str:
        """Format timedelta as HH:MM:SS."""

        total_seconds = int(duration.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    # --------------------------------------------------------
    # 8. Events-per-Hour Report
    # --------------------------------------------------------

    def events_per_hour_report(self) -> None:
        """
        Count valid events for each hour of the day
        and identify all peak-usage hours
        """

        events_by_hour = {hour: 0 for hour in range(24)}

        for entry in self.entries:
            events_by_hour[entry.timestamp.hour] += 1

        self._print_header("EVENTS-PER-HOUR REPORT")

        if not self.entries:
            print("No events found.")
            print(LINE)
            return

        print(f"{'Hour':<15}{'Number of Events'}")

        # Display all 24 hours so zero-activity periods are visible.
        for hour in range(24):
            print(f"{hour:02d}:00{'':<10}{events_by_hour[hour]}")

        max_events = max(events_by_hour.values())

        peak_hours = [
            hour
            for hour, count in events_by_hour.items()
            if count == max_events
        ]

        print("\nPeak Usage Time:")

        for hour in peak_hours:
            print(
                f"{hour:02d}:00 - {max_events} "
                f"{'event' if max_events == 1 else 'events'}"
            )

        print(LINE)

    # --------------------------------------------------------
    # 9. General Log Summary
    # --------------------------------------------------------

    def general_log_summary(self) -> None:
        """
        Display a general summary:
        total lines, valid/invalid lines, log-level counts,
        module counts, and all busiest module(s).
        """

        level_count: dict[str, int] = {
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0,
            "CRITICAL": 0,
        }

        module_count: dict[str, int] = {}

        for entry in self.entries:
            level_count[entry.log_level] = (
                level_count.get(entry.log_level, 0) + 1
            )

            module_count[entry.module] = (
                module_count.get(entry.module, 0) + 1
            )

        self._print_header("GENERAL LOG SUMMARY")

        print("Total file lines:", self.total_lines)
        print("Valid log entries:", len(self.entries))
        print("Invalid lines skipped:", self.invalid_lines)

        print(f"\n{'Log Level':<22}{'Count'}")

        # Keep required levels first.
        required_levels = ["INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in required_levels:
            print(f"{level:<22}{level_count.get(level, 0)}")


        print(f"\n{'Module':<22}{'Events'}")

        if not module_count:
            print(f"{'None':<22}0")
        else:
            for module, count in sorted(
                module_count.items(),
                key=lambda item: (-item[1], item[0]),
            ):
                print(f"{module:<22}{count}")

        if not module_count:
            print("\nBusiest module: None")
        else:
            busiest_count = max(module_count.values())

            busiest_modules = sorted(
                module
                for module, count in module_count.items()
                if count == busiest_count
            )

            print("\nBusiest Module(s):")

            for module in busiest_modules:
                print(f"{module} - {busiest_count} events")

        print(LINE)

    # --------------------------------------------------------
    # Run All Reports
    # --------------------------------------------------------

    def run_all_reports(
        self,
        username: Optional[str] = None,
    ) -> None:
        """Run all nine reports in project order."""

        self.failed_login_report()
        print()

        self.query_activity_summary()
        print()

        self.slow_query_detector()
        print()

        self.transaction_report()
        print()

        self.critical_events_report()
        print()

        if username is not None:
            self.user_activity_report(username)
        else:
            print(LINE)
            print("USER ACTIVITY REPORT")
            print(LINE)
            print(
                "Skipped in --all mode because no username "
                "was supplied."
            )
            print(
                "Use --username USERNAME to include Task 6."
            )
            print(LINE)

        print()
        self.login_logout_session_report()
        print()

        self.events_per_hour_report()
        print()

        self.general_log_summary()




def display_name() -> None:
    """Display the program title and student names."""

    print("\nBANK DATABASE SERVER LOG ANALYZER")
    print("By Yasmin - 1230271")
    print("By Sanabel - 1230288")


def display_menu() -> None:
    """Display the interactive menu."""

    print(LINE)
    print("MAIN MENU")
    print(LINE)
    print("1. Failed Login Report")
    print("2. Query Activity Summary")
    print("3. Slow Query Detector")
    print("4. Transaction Report")
    print("5. Critical Events Report")
    print("6. User Activity Report")
    print("7. Login/Logout Session Report")
    print("8. Events-per-Hour Report")
    print("9. General Log Summary")
    print("10. Run All Reports")
    print("0. Exit")


def run_report(
    analyzer: LogAnalyzer,
    report: str,
    username: Optional[str] = None,
) -> None:
    """Run one report selected from the command line."""

    match report:
        case "failed":
            analyzer.failed_login_report()

        case "query":
            analyzer.query_activity_summary()

        case "slow":
            analyzer.slow_query_detector()

        case "transaction":
            analyzer.transaction_report()

        case "critical":
            analyzer.critical_events_report()

        case "user":
            analyzer.user_activity_report(username)

        case "session":
            analyzer.login_logout_session_report()

        case "hourly":
            analyzer.events_per_hour_report()

        case "summary":
            analyzer.general_log_summary()

        case "all":
            analyzer.run_all_reports(username)

        case _:
            print("Invalid report.")

def interactive_menu(analyzer: LogAnalyzer) -> None:
    """Display the interactive menu and run the selected report."""
    while True:
        print()
        display_menu()

        choice = input("\nEnter your choice: ").strip()

        match choice:
            case "1":
                analyzer.failed_login_report()

            case "2":
                analyzer.query_activity_summary()

            case "3":
                analyzer.slow_query_detector()

            case "4":
                analyzer.transaction_report()

            case "5":
                analyzer.critical_events_report()

            case "6":
                analyzer.user_activity_report()

            case "7":
                analyzer.login_logout_session_report()

            case "8":
                analyzer.events_per_hour_report()

            case "9":
                analyzer.general_log_summary()

            case "10" :
                username = input(
                    "Optional username for User Activity "
                    "(press Enter to skip): "
                ).strip()

                analyzer.run_all_reports(
                    username if username else None
                )

            case "0":
                print("\nGoodbye!")
                break

            case _:
                print("\nInvalid choice. Please try again.")

# ------------------------------------------------------------
# Command-Line Interface
# ------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    """Create and return the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description="Bank Database Server Log Analyzer"
    )

    parser.add_argument(
        "filename",
        nargs="?",
        help=(
            "Path to the bank server log file. "
            "If omitted in menu mode, the program asks for it."
        ),
    )

    parser.add_argument(
        "-r",
        "--report",
        choices=[
            "failed",
            "query",
            "slow",
            "transaction",
            "critical",
            "user",
            "session",
            "hourly",
            "summary",
            "all",
        ],
        help="Run one report directly without opening the menu.",
    )

    parser.add_argument(
        "-u",
        "--username",
        help=(
            "Username used by the user-activity report. "
            "It can also be used with --report all."
        ),
    )

    return parser


# ------------------------------------------------------------
# Main Program
# ------------------------------------------------------------

def main() -> None:
    """Run the Bank Database Server Log Analyzer."""

    args = build_argument_parser().parse_args()

    display_name()

    filename = args.filename

    if not filename:
        filename = input("\nEnter log file name: ").strip()

    if not filename:
        print("Error: Log file name cannot be empty.")
        logging.error("Program started without a log file name.")
        return

    parser = LogParser()

    try:
        entries = parser.parse_file(filename)

    except FileNotFoundError:
        print("Error: File not found.")
        logging.error("Log file not found: %s", filename)
        return

    except PermissionError:
        print("Error: Permission denied while opening the log file.")
        logging.error("Permission denied for log file: %s", filename)
        return

    except UnicodeDecodeError:
        print("Error: Could not decode the log file.")
        logging.error("Could not decode log file: %s", filename)
        return

    except OSError as error:
        print("Error: Could not read the log file.")
        logging.error(
            "OS error while reading %s: %s",
            filename,
            error,
        )
        return

    analyzer = LogAnalyzer(
        entries=entries,
        total_lines=parser.total_lines,
        invalid_lines=parser.invalid_lines,
    )

    # Non-interactive CLI mode.
    if args.report:
        if args.report == "user" and not args.username:
            print("Error: --username is required for the user report.")
            return

        run_report(
            analyzer,
            args.report,
            args.username,
        )
        return

    # Interactive menu mode.
    interactive_menu(analyzer)


if __name__ == "__main__":
    main()
